Utilities for Linux Systems Administration and Daily Use
========================================================

asuswrt-*
---------
Backup/restore configuration - NVRAM only - of devices running AsusWRT firmware.

dircksum
--------
Recursively compute and save/verify the checksum for the given directory.
The checksum information will be saved in the '.dircksum' file within that
directory.

dns-make-in-addr.arpa
---------------------
Generate the reverse lookup zone corresponging to the given IPv4 segment
and given DNS forward resources.

dns-make-ip6.arpa
-----------------
Generate the reverse lookup zone corresponging to the given IPv6 segment
(which length MUST match 16-bit multiple) and given DNS forward resources.

huawei-wctl
-----------
Control Huawei E303s-2 (and compatible) 3G/UMTS USB dongle via its web API.

kernel [directory]
------------------
Deal with the Linux kernel with less headaches.

kvm-helper
----------
Launch a KVM virtual server (guest) with appropriate options for the
requested mode.

makejail-ssh
------------
Create a chroot-ed resources for jailed SSH proxying:
  ProxyCommand ssh username@host netcat -w 1 %h %p 2> /dev/null

mysql-backup
------------
Backup a MySQL database according to the connection parameters specified
in the configuration file(s).

pgsql-backup
------------
Backup a PostgreSQL database according to the connection parameters specified
in the configuration file(s).

rsync-backup
------------
Backup (RSync) a given remote host according to the parameters specified in
the configuration file(s).

server-backup
-------------
Backup (tar) the given server according to the parameters specified in the
configuration file(s).

tar-backup
----------
Backup (tar) given directories according to the parameters specified in the
configuration file(s).

tomato-backup
-------------
Backup configuration - NVRAM or standard (web) - of devices running Tomato
firmware.

zfs [directory]
---------------
A bunch of scripts to go along ZFS on Linux

