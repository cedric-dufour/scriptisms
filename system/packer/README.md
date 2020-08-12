Creating VM Images with HashiCorp Packer
========================================

This directory contains the sample resources required to create minimalistic
VM images using [HashiCorp Packer][packer], along [Debian preseeding][preseed].

[packer]: https://www.packer.io/ "Packer: Build Automated Machine Images"
[preseed]: https://www.debian.org/releases/stable/amd64/apb.en.html "Debian: Automating the installation using preseeding"

In order to build a given image - e.g. `buster` - switch to the ad-hoc directory
and launch `packer`:

```bash
$ cd buster
$ packer build packer.json
```

How it Works
------------

Packer uses [QEMU][qemu] to create the VM using its [QEMU Builder][packer-qemu],
leveraging the [QEMU SLIRP][qemu-slirp] networking stack to make the `.cfg` preseed
file - among other dependencies - available via the `http://10.0.2.2:8080` HTTP endpoint.

[qemu]: https://www.qemu.org/ "QEMU: the FAST! processor emulator"
[packer-qemu]: https://www.packer.io/docs/builders/qemu "Packer: QEMU Builder"
[qemu-slirp]: https://wiki.qemu.org/Documentation/Networking#User_Networking_.28SLIRP.29 "QEMU User Networking (SLIRP)"


Debugging
---------

In order to debug the creation process, start Packer in `debug` mode:

```bash
$ cd buster
$ packer build -debug packer.json
```

Press `<enter>` for each proposed step until you reach the `boot command` step:

```text
==> qemu: Connecting to VM via VNC (127.0.0.1:5993)
==> qemu: Typing the boot command over VNC...
==> qemu: Pausing after run of step 'boot_command: <esc><wait5>expert<spacebar>ipv6.disable=1<spacebar>net.ifnames=0<spacebar>auto=true<spacebar>priority=critical<spacebar>url=http://10.0.2.2:8080/virtual-host.cfg<wait5><enter>'. Press enter to continue. 
```

Note the VNC port being used and launch your VNC viewer; e.g. `gvncviewer`:

```bash
$ gvncviewer 127.0.0.1:93  # 5993-5900=93
```

**WARNING:** Do NOT launch your VNC viewer before the `boot_command` as been typed
by Packer (or its VNC session will be interrupted and the build fail)!

You should see the installer screen and be able to interact with it.


Sample Output
-------------

It's magic!!!

```text
==> qemu: Retrieving ISO
==> qemu: Trying https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/debian-10.5.0-amd64-netinst.iso
==> qemu: Trying https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/debian-10.5.0-amd64-netinst.iso?checksum=sha256%3A93863e17ac24eeaa347dfb91dddac654f214c189e0379d7c28664a306e0301e7
==> qemu: Creating required virtual machine disks
==> qemu: Starting HTTP server on port 8080
==> qemu: Found port for communicator (SSH, WinRM, etc): 2854.
==> qemu: Looking for available port between 5900 and 6000 on 127.0.0.1
==> qemu: Starting VM, booting from CD-ROM
==> qemu: Overriding defaults Qemu arguments with QemuArgs...
==> qemu: Waiting 5s for boot...
==> qemu: Connecting to VM via VNC (127.0.0.1:5999)
==> qemu: Typing the boot command over VNC...
==> qemu: Using ssh communicator to connect: 127.0.0.1
==> qemu: Waiting for SSH to become available...
==> qemu: Connected to SSH!
==> qemu: Uploading /packer/buster/provision.sh => /tmp/
provision.sh 16.14 KiB / 16.14 KiB [==============================================================================================================================================================================================================================] 100.00% 0s
==> qemu: Provisioning with shell script: /tmp/packer-shell150527804
    qemu: ============================================================================
    qemu: BEGIN{apt_update}
    qemu: END{apt_update}
    qemu: ============================================================================
    qemu: BEGIN{clean_packages}
    qemu: openssh-server set to manually installed.
    qemu: Reading package lists...
    qemu: Building dependency tree...
    qemu: Reading state information...
    qemu: Package 'aptitude' is not installed, so not removed
    qemu: Package 'aptitude-common' is not installed, so not removed
    qemu: Package 'avahi-autoipd' is not installed, so not removed
    qemu: Package 'blends-tasks' is not installed, so not removed
    qemu: Package 'bluetooth' is not installed, so not removed
    qemu: Package 'bluez' is not installed, so not removed
    qemu: Package 'os-prober' is not installed, so not removed
    qemu: Package 'wbritish' is not installed, so not removed
    qemu: The following packages will be REMOVED:
    qemu:   dictionaries-common* discover* discover-data* dmidecode* eject*
    qemu:   emacsen-common* iamerican* ibritish* ienglish-common* installation-report*
    qemu:   ispell* laptop-detect* libdiscover2* libusb-0.1-4* nano* task-english*
    qemu:   task-ssh-server* tasksel* tasksel-data* wamerican*
    qemu: 0 upgraded, 0 newly installed, 20 to remove and 0 not upgraded.
    qemu: After this operation, 11.0 MB disk space will be freed.
    qemu: (Reading database ... 21802 files and directories currently installed.)
    qemu: Removing ibritish (3.4.00-6) ...
    qemu: Removing iamerican (3.4.00-6) ...
    qemu: Removing dictionaries-common (1.28.1) ...
    qemu: Removing 'diversion of /usr/share/dict/words to /usr/share/dict/words.pre-dictionaries-common by dictionaries-common'
    qemu: Removing discover (2.1.2-8) ...
    qemu: Removing libdiscover2 (2.1.2-8) ...
    qemu: Removing discover-data (2.2013.01.11) ...
    qemu: Removing dmidecode (3.2-1) ...
    qemu: Removing eject (2.1.5+deb1+cvs20081104-13.2) ...
    qemu: Removing emacsen-common (3.0.4) ...
    qemu: Removing ienglish-common (3.4.00-6) ...
    qemu: Removing installation-report (2.71) ...
    qemu: Removing ispell (3.4.00-6+b1) ...
    qemu: Removing laptop-detect (0.16) ...
    qemu: Removing libusb-0.1-4:amd64 (2:0.1.12-32) ...
    qemu: Removing nano (3.2-3) ...
    qemu: update-alternatives: using /usr/bin/vim.tiny to provide /usr/bin/editor (editor) in auto mode
    qemu: Removing task-english (3.53) ...
    qemu: Removing task-ssh-server (3.53) ...
    qemu: Removing wamerican (2018.04.16-1) ...
    qemu: Removing tasksel (3.53) ...
    qemu: Removing tasksel-data (3.53) ...
    qemu: Processing triggers for libc-bin (2.28-10) ...
    qemu: (Reading database ... 21279 files and directories currently installed.)
    qemu: Purging configuration files for iamerican (3.4.00-6) ...
    qemu: Purging configuration files for ibritish (3.4.00-6) ...
    qemu: Purging configuration files for dictionaries-common (1.28.1) ...
    qemu: Purging configuration files for libdiscover2 (2.1.2-8) ...
    qemu: Purging configuration files for installation-report (2.71) ...
    qemu: Purging configuration files for tasksel (3.53) ...
    qemu: Purging configuration files for emacsen-common (3.0.4) ...
    qemu: Purging configuration files for wamerican (2018.04.16-1) ...
    qemu: Purging configuration files for nano (3.2-3) ...
    qemu: Purging configuration files for discover (2.1.2-8) ...
    qemu: END{clean_packages}
    qemu: ============================================================================
    qemu: BEGIN{clean_libraries}
    qemu: Reading package lists...
    qemu: Building dependency tree...
    qemu: Reading state information...
    qemu: The following packages will be REMOVED:
    qemu:   libpam-systemd*
    qemu: 0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.
    qemu: After this operation, 406 kB disk space will be freed.
    qemu: (Reading database ... 21272 files and directories currently installed.)
    qemu: Removing libpam-systemd:amd64 (241-7~deb10u4) ...
    qemu: END{clean_libraries}
    qemu: ============================================================================
    qemu: BEGIN{preconfig_udev_ifnames}
    qemu: END{preconfig_udev_ifnames}
    qemu: ============================================================================
    qemu: BEGIN{preconfig_initramfs}
    qemu: update-initramfs: Generating /boot/initrd.img-4.19.0-10-amd64
    qemu: END{preconfig_initramfs}
    qemu: ============================================================================
    qemu: BEGIN{preconfig_grub}
    qemu: Generating grub configuration file ...
    qemu: Found linux image: /boot/vmlinuz-4.19.0-10-amd64
    qemu: Found initrd image: /boot/initrd.img-4.19.0-10-amd64
    qemu: done
    qemu: END{preconfig_grub}
    qemu: ============================================================================
    qemu: BEGIN{preconfig_fstab}
    qemu: END{preconfig_fstab}
    qemu: ============================================================================
    qemu: BEGIN{preconfig_hosts}
    qemu: END{preconfig_hosts}
    qemu: ============================================================================
    qemu: BEGIN{apt_dist_upgrade}
    qemu: Reading package lists...
    qemu: Building dependency tree...
    qemu: Reading state information...
    qemu: Calculating upgrade...
    qemu: 0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
    qemu: Reading package lists...
    qemu: Building dependency tree...
    qemu: Reading state information...
    qemu: 0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
    qemu: END{apt_dist_upgrade}
    qemu: ============================================================================
    qemu: BEGIN{clean_apt}
    qemu: END{clean_apt}
    qemu: ============================================================================
    qemu: BEGIN{clean_history}
    qemu: removed '/var/log/faillog'
    qemu: removed '/var/log/auth.log'
    qemu: removed '/var/log/lastlog'
    qemu: removed '/var/log/apt/term.log'
    qemu: removed '/var/log/apt/history.log'
    qemu: removed '/var/log/kern.log'
    qemu: removed '/var/log/syslog'
    qemu: removed '/var/log/dpkg.log'
    qemu: removed '/var/log/daemon.log'
    qemu: removed '/var/log/alternatives.log'
    qemu: removed '/var/log/messages'
    qemu: END{clean_history}
    qemu: ============================================================================
    qemu: BEGIN{zero_freespace}
    qemu: dd: error writing '/ZERO': No space left on device
    qemu: 1377+0 records in
    qemu: 1376+0 records out
    qemu: 1443594240 bytes (1.4 GB, 1.3 GiB) copied, 1.49228 s, 967 MB/s
    qemu: dd: error writing '/boot/ZERO': No space left on device
    qemu: 435+0 records in
    qemu: 434+0 records out
    qemu: 455753728 bytes (456 MB, 435 MiB) copied, 0.761037 s, 599 MB/s
    qemu: dd: error writing '/tmp/ZERO': No space left on device
    qemu: 477+0 records in
    qemu: 476+0 records out
    qemu: 500068352 bytes (500 MB, 477 MiB) copied, 0.332749 s, 1.5 GB/s
    qemu: dd: error writing '/var/ZERO': No space left on device
    qemu: 830+0 records in
    qemu: 829+0 records out
    qemu: 869978112 bytes (870 MB, 830 MiB) copied, 0.994101 s, 875 MB/s
    qemu: dd: error writing '/dev/mapper/vg.local-lv.swap': No space left on device
    qemu: 993+0 records in
    qemu: 992+0 records out
    qemu: 1040187392 bytes (1.0 GB, 992 MiB) copied, 1.18394 s, 879 MB/s
    qemu: Setting up swapspace version 1, size = 992 MiB (1040183296 bytes)
    qemu: no label, UUID=a21d6180-b9d5-4181-82ad-a7d247268c08
    qemu: END{zero_freespace}
==> qemu: Gracefully halting virtual machine...
    qemu: ============================================================================
    qemu: BEGIN{clean_apt}
    qemu: END{clean_apt}
    qemu: ============================================================================
    qemu: BEGIN{clean_history}
    qemu: END{clean_history}
    qemu: ============================================================================
    qemu: BEGIN{clean_root_ssh}
    qemu: removed '/root/.ssh/authorized_keys'
    qemu: removed directory '/root/.ssh'
    qemu: END{clean_root_ssh}
    qemu: ============================================================================
    qemu: BEGIN{clean_network}
    qemu: removed '/var/lib/dhcp/dhclient.eth0.leases'
    qemu: END{clean_network}
    qemu: ============================================================================
    qemu: BEGIN{clean_self}
    qemu: removed '/tmp/provision.sh'
    qemu: END{clean_self}
    qemu: ============================================================================
    qemu: BEGIN{clean_shutdown}
    qemu: END{clean_shutdown}
==> qemu: Converting hard drive...
Build 'qemu' finished.

==> Builds finished. The artifacts of successful builds are:
--> qemu: VM files in directory: /local/data/unencrypted/packer/buster/output
```

It's works!!!

```bash
$ ls -lh output/
-rw-r--r-- 1 thomas anderson 289M Aug 12 10:41 buster.qcow2
```

(Yeah! That's only a 289MiB image file!)

