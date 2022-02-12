obj-m += teth.o
iproute2-repo = ~/iproute2-repo

all: teth.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


teth.ko: teth.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

testp: all
	-sudo rmmod teth.ko
	sudo modprobe ptp
	sudo dmesg -C
	sudo insmod teth.ko
	sudo $(iproute2-repo)/ip/ip link add teth1 type teth peer name teth2

	#sudo $(iproute2-repo)/ip/ifcfg teth1 add 192.168.69.1
	sudo ip link set dev teth1 up	
	#sudo $(iproute2-repo)/ip/ifcfg teth2 add 192.168.69.2
	sudo ip link set dev teth2 up

	@echo "------"
	@ethtool -T teth1
	@echo "------"

	@echo "PTP clocks"
	@ls /dev/ptp*
	ls /dev/ptp* | head -1 | xargs -I{} sudo ./testptp -d {} -T 1000000
	ls /dev/ptp* | tail -1 | xargs -I{} sudo ./testptp -d {} -T 2000000
	ls /dev/ptp* | xargs -I{} sudo ./testptp -d {} -g -c
	@echo "------"

	#sudo ./hwtstamp_config teth1 ON NONE
	#sudo ./hwtstamp_config teth2 ON NONE

test: testp
	sudo rmmod teth.ko
	dmesg
