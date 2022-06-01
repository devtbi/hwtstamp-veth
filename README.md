# hwtstamp-veth
Linux virtual ethernet interface with basic emulated hardware timestamping capability

# Preconditions
- Linux Kernel 5.13.0
- Installed linux-headers package for kernel
- testptp in path (https://github.com/torvalds/linux/blob/master/tools/testing/selftests/ptp/testptp.c)
- iproute2 sources (https://github.com/shemminger/iproute2), tested with 7a49ff9d7906858ec75b69e9ad05af2bfd9cab4d

# Compilation
- Apply iproute2 patch to iproute2 sources
- Build iproute2 with make
- Update iproute2 path in Makefile from hwtstamp-veth
- Build hwtstamp-veth with make

