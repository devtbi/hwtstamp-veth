/*
 *  code based on drivers/net/veth.c, modified to include hardware timestamping
 *
 *  Original Source Code Repository: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/
 *
 */

#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/u64_stats_sync.h>

#include <net/rtnetlink.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <linux/veth.h>
#include <linux/module.h>

#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/timecounter.h>
#include <linux/sockios.h>
#include <linux/bits.h>
#include <linux/ktime.h>
#include <linux/sched_clock.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/jiffies.h>

#define IGB_PTP_ENABLED BIT(0)

#define DRV_NAME "teth"
#define DRV_VERSION "0.1"

#define RX_SKB_IN_FLIGHT_LEN 3

struct teth_priv;

struct teth_rxw_container
{
	struct delayed_work rx_work;
	struct teth_priv *priv;
	struct sk_buff *skb;
};

struct teth_priv
{
	struct net_device __rcu *peer;
	atomic64_t dropped;
	unsigned requested_headroom;

	struct ptp_clock *ptp_clock;
	struct ptp_clock_info ptp_clock_info;

	struct hwtstamp_config tstamp_config;
	unsigned int ptp_flags;
	spinlock_t tmreg_lock;
	struct cyclecounter cc;
	struct timecounter tc;
	bool pps_sys_wrap_on;
	u64 tx_delay;
	u64 rx_delay;

	spinlock_t rx_skb_in_flight_lock;
	int rx_skb_in_flight_write_idx;
	struct teth_rxw_container rx_work[RX_SKB_IN_FLIGHT_LEN];
};

/*
 * ethtool interface
 */

static struct
{
	const char string[ETH_GSTRING_LEN];
} ethtool_stats_keys[] = {
	{"peer_ifindex"},
};

static int teth_get_link_ksettings(struct net_device *dev,
								   struct ethtool_link_ksettings *cmd)
{
	cmd->base.speed = SPEED_10000;
	cmd->base.duplex = DUPLEX_FULL;
	cmd->base.port = PORT_TP;
	cmd->base.autoneg = AUTONEG_DISABLE;
	return 0;
}

static void teth_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, DRV_VERSION, sizeof(info->version));
}

static void teth_get_strings(struct net_device *dev, u32 stringset, u8 *buf)
{
	switch (stringset)
	{
	case ETH_SS_STATS:
		memcpy(buf, &ethtool_stats_keys, sizeof(ethtool_stats_keys));
		break;
	}
}

static int teth_get_sset_count(struct net_device *dev, int sset)
{
	switch (sset)
	{
	case ETH_SS_STATS:
		return ARRAY_SIZE(ethtool_stats_keys);
	default:
		return -EOPNOTSUPP;
	}
}

static void teth_get_ethtool_stats(struct net_device *dev,
								   struct ethtool_stats *stats, u64 *data)
{
	struct teth_priv *priv = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(priv->peer);

	data[0] = peer ? peer->ifindex : 0;
}

static int teth_get_ts_info(struct net_device *dev,
							struct ethtool_ts_info *info)
{
	struct teth_priv *priv = netdev_priv(dev);

	if (priv->ptp_clock)
		info->phc_index = ptp_clock_index(priv->ptp_clock);
	else
		info->phc_index = -1;

	info->so_timestamping =
		SOF_TIMESTAMPING_TX_SOFTWARE |
		SOF_TIMESTAMPING_RX_SOFTWARE |
		SOF_TIMESTAMPING_SOFTWARE |
		SOF_TIMESTAMPING_TX_HARDWARE |
		SOF_TIMESTAMPING_RX_HARDWARE |
		SOF_TIMESTAMPING_RAW_HARDWARE;

	info->tx_types =
		BIT(HWTSTAMP_TX_OFF) |
		BIT(HWTSTAMP_TX_ON);

	info->rx_filters = BIT(HWTSTAMP_FILTER_NONE);

	info->rx_filters |=
		BIT(HWTSTAMP_FILTER_PTP_V1_L4_SYNC) |
		BIT(HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ) |
		BIT(HWTSTAMP_FILTER_PTP_V2_EVENT);

	return 0;
}

static const struct ethtool_ops teth_ethtool_ops = {
	.get_drvinfo = teth_get_drvinfo,
	.get_link = ethtool_op_get_link,
	.get_strings = teth_get_strings,
	.get_sset_count = teth_get_sset_count,
	.get_ethtool_stats = teth_get_ethtool_stats,
	.get_link_ksettings = teth_get_link_ksettings,
	.get_ts_info = teth_get_ts_info,
};

static void teth_rx_work(struct work_struct *work)
{
	struct teth_rxw_container *rxwc = container_of(to_delayed_work(work), struct teth_rxw_container,
												   rx_work);
	struct teth_priv *priv = rxwc->priv;
	struct net_device *rcv;
	struct teth_priv *rcv_priv;
	unsigned long flags;
	struct sk_buff *rx_skb;

	rcu_read_lock();
	rcv = rcu_dereference(priv->peer);
	rcv_priv = netdev_priv(rcv);

	spin_lock_irqsave(&priv->rx_skb_in_flight_lock, flags);
	rx_skb = rxwc->skb;
	rxwc->skb = NULL;
	spin_unlock_irqrestore(&priv->rx_skb_in_flight_lock, flags);

	if (unlikely(!rcv))
	{
		dev_kfree_skb_any(rx_skb);
		goto drop;
	}

	spin_lock_irqsave(&rcv_priv->tmreg_lock, flags);
	skb_hwtstamps(rx_skb)->hwtstamp = ns_to_ktime(timecounter_read(&rcv_priv->tc));
	spin_unlock_irqrestore(&rcv_priv->tmreg_lock, flags);

	if (likely(dev_forward_skb(rcv, rx_skb) == NET_RX_SUCCESS))
	{
	}
	else
	{
	drop:
		atomic64_inc(&priv->dropped); // rx-drop
	}

	rcu_read_unlock();
}

static netdev_tx_t teth_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct teth_priv *priv = netdev_priv(dev);
	int dropped = 0;
	struct net_device *rcv;
	struct teth_priv *rcv_priv;
	struct sk_buff *rcv_skb;
	u32 skblen = 0;

	struct skb_shared_hwtstamps shhwtstamps;

	rcu_read_lock();
	rcv = rcu_dereference(priv->peer);
	rcv_priv = netdev_priv(rcv);
	if (unlikely(!rcv))
	{
		kfree_skb(skb);
		dropped = 1; // tx-drop
	}
	else
	{
		unsigned long flags;
		struct sk_buff *rx_skb;
		struct teth_rxw_container *rxwc;

		ndelay(priv->tx_delay);

		// hw tsmp?
		if (skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)
		{
			unsigned long flags;
			spin_lock_irqsave(&priv->tmreg_lock, flags);
			shhwtstamps.hwtstamp = ns_to_ktime(timecounter_read(&priv->tc));
			spin_unlock_irqrestore(&priv->tmreg_lock, flags);

			skb_tstamp_tx(skb, &shhwtstamps);
		}
		else
		{
			skb_tx_timestamp(skb);
		}
		rcv_skb = skb_copy(skb, GFP_ATOMIC);
		skblen = rcv_skb->len;
		consume_skb(skb);

		// TODO check if rx tstamp
		// TODO add delay

		// else
		// {
		/* Notify the stack and free the skb after we've unlocked */

		// }
		//
		spin_lock_irqsave(&priv->rx_skb_in_flight_lock, flags);
		rxwc = &priv->rx_work[priv->rx_skb_in_flight_write_idx];
		spin_unlock_irqrestore(&priv->rx_skb_in_flight_lock, flags);
		if (!rxwc->skb) // pakcet set to NULL means either unused or work has set it to null
		{
			cancel_delayed_work_sync(&rxwc->rx_work); // wait for work to finish
			spin_lock_irqsave(&priv->rx_skb_in_flight_lock, flags);
			rxwc->skb = rcv_skb;
			schedule_delayed_work_on(get_cpu(), &rxwc->rx_work, nsecs_to_jiffies64(priv->rx_delay));
			spin_unlock_irqrestore(&priv->rx_skb_in_flight_lock, flags);
			priv->rx_skb_in_flight_write_idx = (priv->rx_skb_in_flight_write_idx + 1) % RX_SKB_IN_FLIGHT_LEN;
		}
		else
		{
			dropped = 1; // rx-drop
		}
	}

	if (dropped)
	{
		atomic64_inc(&priv->dropped);
	}
	else
	{
		// stats cannot be updated in locked state
		dev_lstats_add(dev, skblen);
	}

	// TODO free things
	rcu_read_unlock();
	return NETDEV_TX_OK;
}

/*
 * general routines
 */

static u64 teth_stats_(struct net_device *dev, u64 *packets, u64 *bytes)
{
	struct teth_priv *priv = netdev_priv(dev);

	dev_lstats_read(dev, packets, bytes);
	return atomic64_read(&priv->dropped);
}

static void teth_get_stats64(struct net_device *dev,
							 struct rtnl_link_stats64 *tot)
{
	struct teth_priv *priv = netdev_priv(dev);
	struct net_device *peer;
	u64 packets, bytes;

	tot->tx_dropped = teth_stats_(dev, &packets, &bytes);
	tot->tx_bytes = bytes;
	tot->tx_packets = packets;

	rcu_read_lock();
	peer = rcu_dereference(priv->peer);
	if (peer)
	{
		teth_stats_(peer, &packets, &bytes);
		tot->rx_bytes += bytes;
		tot->rx_packets += packets;
	}
	rcu_read_unlock();
}

/* fake multicast ability */
static void teth_set_multicast_list(struct net_device *dev)
{
}

static int teth_open(struct net_device *dev)
{
	struct teth_priv *priv = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(priv->peer);

	if (!peer)
		return -ENOTCONN;

	if (peer->flags & IFF_UP)
	{
		netif_carrier_on(dev);
		netif_carrier_on(peer);
	}
	return 0;
}

static void teth_rx_skb_in_fligh_reset(struct teth_priv *priv)
{
	int i;
	priv->rx_skb_in_flight_write_idx = 0;
	for (i = 0; i < RX_SKB_IN_FLIGHT_LEN; ++i)
	{
		struct teth_rxw_container *rxwc = &priv->rx_work[i];
		rxwc->skb = NULL;
		rxwc->priv = priv;
		INIT_DELAYED_WORK(&rxwc->rx_work, teth_rx_work);
	}
}

static void teth_rx_skb_in_fligh_free(struct teth_priv *priv)
{
	unsigned long flags;
	int i;
	for (i = 0; i < RX_SKB_IN_FLIGHT_LEN; ++i)
	{
		struct teth_rxw_container *rxwc = &priv->rx_work[i];
		cancel_delayed_work_sync(&rxwc->rx_work);
	}
	spin_lock_irqsave(&priv->rx_skb_in_flight_lock, flags);
	for (i = 0; i < RX_SKB_IN_FLIGHT_LEN; ++i)
	{
		struct teth_rxw_container *rxwc = &priv->rx_work[i];
		dev_kfree_skb_any(rxwc->skb);
		//TODO update dropped stats (not in interrupt)
	}
	spin_unlock_irqrestore(&priv->rx_skb_in_flight_lock, flags);
}

static int teth_close(struct net_device *dev)
{
	struct teth_priv *priv = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(priv->peer);

	netif_carrier_off(dev);
	if (peer)
		netif_carrier_off(peer);

	teth_rx_skb_in_fligh_free(netdev_priv(dev));

	return 0;
}

static int is_valid_teth_mtu(int mtu)
{
	return mtu >= ETH_MIN_MTU && mtu <= ETH_MAX_MTU;
}

static int teth_dev_init(struct net_device *dev)
{
	dev->lstats = netdev_alloc_pcpu_stats(struct pcpu_lstats);
	if (!dev->lstats)
		return -ENOMEM;

	return 0;
}

static void teth_dev_free(struct net_device *dev)
{
	struct teth_priv *priv = netdev_priv(dev);
	free_percpu(dev->lstats);

	if (priv->ptp_clock)
		ptp_clock_unregister(priv->ptp_clock);
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void teth_poll_controller(struct net_device *dev)
{
	/* veth only receives frames when its peer sends one
	 * Since it's a synchronous operation, we are guaranteed
	 * never to have pending data when we poll for it so
	 * there is nothing to do here.
	 *
	 * We need this though so netpoll recognizes us as an interface that
	 * supports polling, which enables bridge devices in virt setups to
	 * still use netconsole
	 */
}
#endif /* CONFIG_NET_POLL_CONTROLLER */

static int teth_get_iflink(const struct net_device *dev)
{
	struct teth_priv *priv = netdev_priv(dev);
	struct net_device *peer;
	int iflink;

	rcu_read_lock();
	peer = rcu_dereference(priv->peer);
	iflink = peer ? peer->ifindex : 0;
	rcu_read_unlock();

	return iflink;
}

static void teth_set_rx_headroom(struct net_device *dev, int new_hr)
{
	struct teth_priv *peer_priv, *priv = netdev_priv(dev);
	struct net_device *peer;

	if (new_hr < 0)
		new_hr = 0;

	rcu_read_lock();
	peer = rcu_dereference(priv->peer);
	if (unlikely(!peer))
		goto out;

	peer_priv = netdev_priv(peer);
	priv->requested_headroom = new_hr;
	new_hr = max(priv->requested_headroom, peer_priv->requested_headroom);
	dev->needed_headroom = new_hr;
	peer->needed_headroom = new_hr;

out:
	rcu_read_unlock();
}

static int teth_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd);

static const struct net_device_ops teth_netdev_ops = {
	.ndo_init = teth_dev_init,
	.ndo_open = teth_open,
	.ndo_stop = teth_close,
	.ndo_start_xmit = teth_xmit,
	.ndo_get_stats64 = teth_get_stats64,
	.ndo_set_rx_mode = teth_set_multicast_list,
	.ndo_set_mac_address = eth_mac_addr,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller = teth_poll_controller,
#endif
	.ndo_get_iflink = teth_get_iflink,
	.ndo_features_check = passthru_features_check,
	.ndo_set_rx_headroom = teth_set_rx_headroom,
	.ndo_do_ioctl = teth_ioctl,
};

#define VETH_FEATURES (NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_HW_CSUM |     \
					   NETIF_F_RXCSUM | NETIF_F_SCTP_CRC | NETIF_F_HIGHDMA | \
					   NETIF_F_GSO_SOFTWARE | NETIF_F_GSO_ENCAP_ALL |        \
					   NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_RX |   \
					   NETIF_F_HW_VLAN_STAG_TX | NETIF_F_HW_VLAN_STAG_RX)

static int teth_ptp_clock_feature_enable(struct ptp_clock_info *ptp,
										 struct ptp_clock_request *rq, int on)
{
	return -EOPNOTSUPP; // see igb_ptp_feature_enable_i210 for options
}

static int teth_ptp_clock_adjfreq(struct ptp_clock_info *ptp, s32 ppb)
{
	return -EOPNOTSUPP;
	//TODO (need to do shifty business) - frequency
}

static int teth_ptp_clock_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct teth_priv *priv = container_of(ptp, struct teth_priv,
										  ptp_clock_info);
	unsigned long flags;
	spin_lock_irqsave(&priv->tmreg_lock, flags);

	timecounter_adjtime(&priv->tc, delta);

	spin_unlock_irqrestore(&priv->tmreg_lock, flags);
	return 0;
}

static int teth_ptp_clock_gettime(struct ptp_clock_info *ptp,
								  struct timespec64 *ts)
{
	struct teth_priv *priv = container_of(ptp, struct teth_priv,
										  ptp_clock_info);
	unsigned long flags;
	spin_lock_irqsave(&priv->tmreg_lock, flags);

	*ts = ns_to_timespec64(timecounter_read(&priv->tc));

	spin_unlock_irqrestore(&priv->tmreg_lock, flags);
	return 0;
}

static int teth_ptp_clock_settime(struct ptp_clock_info *ptp,
								  const struct timespec64 *ts)
{
	struct teth_priv *priv = container_of(ptp, struct teth_priv,
										  ptp_clock_info);
	unsigned long flags;
	spin_lock_irqsave(&priv->tmreg_lock, flags);

	timecounter_init(&priv->tc, &priv->cc, timespec64_to_ns(ts));

	spin_unlock_irqrestore(&priv->tmreg_lock, flags);
	return 0;
}

static u64 teth_ptp_clock_read(const struct cyclecounter *cc)
{
	return sched_clock();
}

static void teth_ptp_reset(struct teth_priv *priv)
{
	spin_lock_init(&priv->tmreg_lock);
	spin_lock_init(&priv->rx_skb_in_flight_lock);
	teth_rx_skb_in_fligh_reset(priv);
	// if (priv->ptp_flags & IGB_PTP_OVERFLOW_CHECK)
	// 	INIT_DELAYED_WORK(&adapter->ptp_overflow_work,
	// 					  teth_ptp_overflow_check);

	priv->tstamp_config.rx_filter = HWTSTAMP_FILTER_NONE;
	priv->tstamp_config.tx_type = HWTSTAMP_TX_OFF;

	priv->tx_delay = 100;
	priv->rx_delay = 20000;

	priv->ptp_clock_info.owner = THIS_MODULE;
	priv->ptp_clock_info.max_adj = 1000000000;
	priv->ptp_clock_info.n_ext_ts = 0;
	priv->ptp_clock_info.pps = 0;
	priv->ptp_clock_info.adjfreq = teth_ptp_clock_adjfreq;
	priv->ptp_clock_info.adjtime = teth_ptp_clock_adjtime;
	priv->ptp_clock_info.gettime64 = teth_ptp_clock_gettime;
	priv->ptp_clock_info.settime64 = teth_ptp_clock_settime;
	priv->ptp_clock_info.enable = teth_ptp_clock_feature_enable;
	priv->cc.read = teth_ptp_clock_read;
	priv->cc.mask = CYCLECOUNTER_MASK(64);
	priv->cc.mult = 1;
	priv->cc.shift = 0; //IGB_82576_TSYNC_SHIFT;

	timecounter_init(&priv->tc, &priv->cc, 0);
	priv->ptp_flags |= 0; //IGB_PTP_OVERFLOW_CHECK;
}

static void teth_ptp_setup(struct net_device *netdev)
{
	struct teth_priv *priv = netdev_priv(netdev);
	teth_ptp_reset(priv);
	priv->ptp_clock = ptp_clock_register(&priv->ptp_clock_info, NULL);
	if (IS_ERR(priv->ptp_clock))
	{
		priv->ptp_clock = NULL;
		dev_err(&netdev->dev, "ptp_clock_register failed\n");
	}
	else if (priv->ptp_clock)
	{
		dev_info(&netdev->dev, "added PHC");
		priv->ptp_flags |= IGB_PTP_ENABLED;
	}
}

static void teth_setup(struct net_device *netdev)
{
	ether_setup(netdev);

	netdev->priv_flags &= ~IFF_TX_SKB_SHARING;
	netdev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	netdev->priv_flags |= IFF_NO_QUEUE;
	netdev->priv_flags |= IFF_PHONY_HEADROOM;

	netdev->netdev_ops = &teth_netdev_ops;
	netdev->ethtool_ops = &teth_ethtool_ops;
	netdev->features |= NETIF_F_LLTX;
	netdev->features |= VETH_FEATURES;
	netdev->vlan_features = netdev->features &
							~(NETIF_F_HW_VLAN_CTAG_TX |
							  NETIF_F_HW_VLAN_STAG_TX |
							  NETIF_F_HW_VLAN_CTAG_RX |
							  NETIF_F_HW_VLAN_STAG_RX);
	netdev->needs_free_netdev = true;
	netdev->priv_destructor = teth_dev_free;
	netdev->max_mtu = ETH_MAX_MTU;

	netdev->hw_features = VETH_FEATURES;
	netdev->hw_enc_features = VETH_FEATURES;
	netdev->mpls_features = NETIF_F_HW_CSUM | NETIF_F_GSO_SOFTWARE;

	teth_ptp_setup(netdev);
}

// static int teth_ptp_set_timestamp_mode(struct net_device *netdev, struct hwtstamp_config *ifr)
// {
// 	return 0;
// }

static int teth_ptp_set_ts_config(struct net_device *netdev, struct ifreq *ifr)
{
	struct teth_priv *priv = netdev_priv(netdev);
	struct hwtstamp_config config;
	//	int err;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

	//	err = teth_ptp_set_timestamp_mode(netdev, &config);
	//	if (err)
	//		return err;

	/* save these settings for future reference */
	memcpy(&priv->tstamp_config, &config, sizeof(priv->tstamp_config));

	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) ? -EFAULT : 0;
}

int teth_ptp_get_ts_config(struct net_device *netdev, struct ifreq *ifr)
{
	struct teth_priv *priv = netdev_priv(netdev);
	struct hwtstamp_config *config = &priv->tstamp_config;

	return copy_to_user(ifr->ifr_data, config, sizeof(*config)) ? -EFAULT : 0;
}

/*
* ioctl
*/
static int teth_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	switch (cmd)
	{
	case SIOCGHWTSTAMP:
		return teth_ptp_get_ts_config(netdev, ifr);
	case SIOCSHWTSTAMP:
		return teth_ptp_set_ts_config(netdev, ifr);
	default:
		return -EOPNOTSUPP;
	}
}

/*
 * netlink interface
 */

static int teth_validate(struct nlattr *tb[], struct nlattr *data[],
						 struct netlink_ext_ack *extack)
{
	if (tb[IFLA_ADDRESS])
	{
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	if (tb[IFLA_MTU])
	{
		if (!is_valid_teth_mtu(nla_get_u32(tb[IFLA_MTU])))
			return -EINVAL;
	}
	return 0;
}

static struct rtnl_link_ops teth_link_ops;

static int teth_newlink(struct net *src_net, struct net_device *dev,
						struct nlattr *tb[], struct nlattr *data[],
						struct netlink_ext_ack *extack)
{
	int err;
	struct net_device *peer;
	struct teth_priv *priv;
	char ifname[IFNAMSIZ];
	struct nlattr *peer_tb[IFLA_MAX + 1], **tbp;
	unsigned char name_assign_type;
	struct ifinfomsg *ifmp;
	struct net *net;

	/*
	 * create and register peer first
	 */
	if (data != NULL && data[VETH_INFO_PEER] != NULL)
	{
		struct nlattr *nla_peer;

		nla_peer = data[VETH_INFO_PEER];
		ifmp = nla_data(nla_peer);
		err = rtnl_nla_parse_ifla(peer_tb,
								  nla_data(nla_peer) + sizeof(struct ifinfomsg),
								  nla_len(nla_peer) - sizeof(struct ifinfomsg),
								  NULL);
		if (err < 0)
			return err;

		err = teth_validate(peer_tb, NULL, extack);
		if (err < 0)
			return err;

		tbp = peer_tb;
	}
	else
	{
		ifmp = NULL;
		tbp = tb;
	}

	if (ifmp && tbp[IFLA_IFNAME])
	{
		nla_strscpy(ifname, tbp[IFLA_IFNAME], IFNAMSIZ);
		name_assign_type = NET_NAME_USER;
	}
	else
	{
		snprintf(ifname, IFNAMSIZ, DRV_NAME "%%d");
		name_assign_type = NET_NAME_ENUM;
	}

	net = rtnl_link_get_net(src_net, tbp);
	if (IS_ERR(net))
		return PTR_ERR(net);

	peer = rtnl_create_link(net, ifname, name_assign_type,
							&teth_link_ops, tbp, extack);
	if (IS_ERR(peer))
	{
		put_net(net);
		return PTR_ERR(peer);
	}

	if (!ifmp || !tbp[IFLA_ADDRESS])
		eth_hw_addr_random(peer);

	if (ifmp && (dev->ifindex != 0))
		peer->ifindex = ifmp->ifi_index;

	peer->gso_max_size = dev->gso_max_size;
	peer->gso_max_segs = dev->gso_max_segs;

	err = register_netdevice(peer);
	put_net(net);
	net = NULL;
	if (err < 0)
		goto err_register_peer;

	netif_carrier_off(peer);

	err = rtnl_configure_link(peer, ifmp);
	if (err < 0)
		goto err_configure_peer;

	/*
	 * register dev last
	 *
	 * note, that since we've registered new device the dev's name
	 * should be re-allocated
	 */

	if (tb[IFLA_ADDRESS] == NULL)
		eth_hw_addr_random(dev);

	if (tb[IFLA_IFNAME])
		nla_strscpy(dev->name, tb[IFLA_IFNAME], IFNAMSIZ);
	else
		snprintf(dev->name, IFNAMSIZ, DRV_NAME "%%d");

	err = register_netdevice(dev);
	if (err < 0)
		goto err_register_dev;

	netif_carrier_off(dev);

	/*
	 * tie the deviced together
	 */

	priv = netdev_priv(dev);
	rcu_assign_pointer(priv->peer, peer);

	priv = netdev_priv(peer);
	rcu_assign_pointer(priv->peer, dev);
	return 0;

err_register_dev:
	/* nothing to do */
err_configure_peer:
	unregister_netdevice(peer);
	return err;

err_register_peer:
	free_netdev(peer);
	return err;
}

static void teth_dellink(struct net_device *dev, struct list_head *head)
{
	struct teth_priv *priv;
	struct net_device *peer;

	priv = netdev_priv(dev);
	peer = rtnl_dereference(priv->peer);

	/* Note : dellink() is called from default_device_exit_batch(),
	 * before a rcu_synchronize() point. The devices are guaranteed
	 * not being freed before one RCU grace period.
	 */
	RCU_INIT_POINTER(priv->peer, NULL);
	unregister_netdevice_queue(dev, head);

	if (peer)
	{
		priv = netdev_priv(peer);
		RCU_INIT_POINTER(priv->peer, NULL);
		unregister_netdevice_queue(peer, head);
	}
}

static const struct nla_policy teth_policy[VETH_INFO_MAX + 1] = {
	[VETH_INFO_PEER] = {.len = sizeof(struct ifinfomsg)},
};

static struct net *teth_get_link_net(const struct net_device *dev)
{
	struct teth_priv *priv = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(priv->peer);

	return peer ? dev_net(peer) : dev_net(dev);
}

static struct rtnl_link_ops teth_link_ops = {
	.kind = DRV_NAME,
	.priv_size = sizeof(struct teth_priv),
	.setup = teth_setup,
	.validate = teth_validate,
	.newlink = teth_newlink,
	.dellink = teth_dellink,
	.policy = teth_policy,
	.maxtype = VETH_INFO_MAX,
	.get_link_net = teth_get_link_net,
};

/*
 * init/fini
 */

static __init int teth_init(void)
{
	return rtnl_link_register(&teth_link_ops);
}

static __exit void teth_exit(void)
{
	rtnl_link_unregister(&teth_link_ops);
}

module_init(teth_init);
module_exit(teth_exit);

MODULE_DESCRIPTION("tVirtual Ethernet Tunnel");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_RTNL_LINK(DRV_NAME);
