# HyperNF
HyperNF is a high-performance network backend of the Xen hypervisor.
HyperNF allows VMs to transmit packets in the context of hypercall over the netmap API.

HyperNF is good for NFV applications in terms of throughput, resource utilization and fairness.

This is the reference implementation of "HyperNF: Building a High Performance, High Utilization and Fair NFV Platform" presented in ACM Symposium on Cloud Computing (SoCC) 2017. (to appear)

# Using HyperNF

## Download Xen and netmap, and apply patches

```
$ git submodule update --init

$ cd xen
$ git am ../HyperNF-xen-patch/*

$ cd ..
$ cd netmap
$ git am ../HyperNF-netmap-patch/*
```

## Installing Xen

```
$ cd xen
$ ./configure
$ make dist
$ make install
```

Details are described at [Compiling Xen From Source](https://wiki.xenproject.org/wiki/Compiling_Xen_From_Source).

## Building netmap (in dom0 and domU)

```
$ cd netmap/LINUX
$ make
```

Instruction is found in [the netmap repository](https://github.com/luigirizzo/netmap).

## Building xen-netmapback (in dom0)

Before building the netmapback kernel module, please build netmap.

```
$ cd xen-netmapback
$ cp nmif-vale /etc/xen/scripts
$ make
```

An example script for initialization.

```
rmmod xen_netmapback

ifdown eth1 # NIC for HyperNF, if necessary

rmmod i40e
rmmod netmap

insmod HyperNF/netmap/LINUX/netmap.ko
insmod HyperNF/netmap/LINUX/i40e/i40e.ko
insmod HyperNF/xen-netmapback/xen-netmapback.ko

sleep 0.5
ifup eth1
# disable TSO, GSO, etc...
ethtool -K eth1 tx off rx off tso off gso off gro off lro off sg off ntuple off rxvlan off txvlan off rxhash off highdma off

# set promiscuous mode
ifconfig eth1 promisc

# Set bridge batch size 100
echo 100 > /sys/module/netmap/parameters/bridge_batch
HyperNF/xen-netmapback/tools/xennet_ctrl -o 1 -v 100
HyperNF/xen-netmapback/tools/xennet_ctrl -o 2 -v 0

# set the number of NIC queue
ethtool -L eth1 combined 1

# disable rate-limit
xl sched-credit2 -s -p Pool-0 -r 0

# turn on interface
ifconfig eth1 up
```

## Example of VM boot config (in dom0)

This config creates a VM with one default vif and two netmap interfaces. (The default interface is for ease of management.)

```
name="linux"
kernel="PATH_TO_KERNEL"
vcpus=1
cpus="3"
memory=1024
pvh=1
vif=["mac=00:10:00:00:00:02,bridge=xenbr", "type=nmif,bridge=valex:lx0,script=nmif-vale,mac=00:16:3e:af:12:00", "type=nmif,bridge=valey:ly0,script=nmif-vale,mac=00:17:3e:af:12:00"]
disk=['file:./vmdisk.img,xvda,rw']
extra='root=/dev/xvda1'
```

## Build xen-netmapfront (in domU)

Before building the netmapfront kernel module, please build netmap.

```
$ cd xen-netmapfront
$ make

$ insmod xen-netmapfront.ko

$ ifconfig eth1 up # turn on netmap virtual device
```

## Xen and dom0 Linux boot option

- Increase grant frames by ```gnttab_max_frames=20000 gnttab_max_nr_frames=22000```.

Here is an example.

```
#
DEFAULT netboot
LABEL   netboot
COM32	lib/mboot.c32

# Dom0 14 CPUs, isolcpus=7-13
APPEND	xen-4.8.0.gz dom0pvh=1 sched=credit2 dom0_mem=32768M,max:32768M cpus="0-13" dom0_max_vcpus=14 dom0_vcpus_pin=true loglvl=all guest_loglvl=all intel_iommu=on iommu=on com1=57600,8n1 console=com1 gnttab_max_frames=20000 gnttab_max_nr_frames=22000 --- vmlinuz-4.6.0 ip=::::::dhcp console=hvc0 nousb netboot=nfs nfsroot=NFS_SERVER_ADDR:PATH_TO_DIR,nfsvers=3 rw intel_idle.max_cstate=0 isolcpus=7-13
```

## Example application

- netmap pkt-gen

Dom0 setup
```
$ cd netmap/examples
$ make pkt-gen

$ tasket -c 1 ./pkt-gen -i valex:vtx -f rx
```

DomU setup
```
$ cd netmap/examples
$ make pkt-gen

$ ./pkt-gen -i netmap:eth1 -f tx
```

