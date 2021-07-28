Creating Debian/Buster VM Image with HashiCorp Packer
=====================================================
(make sure to read the generic [README](../README.md) beforehand)

Debian Source
-------------

This sample Debian/Buster Packer-ed VM image uses the `netinst` version of the CD Installer.

To update the version being used, visit
[https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/](https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/)
to see available versions and update the [build.pkr.hcl](./build.pkr.hcl) file accordingly:

```hcl
source "qemu" "buster" {
  iso_url      = "https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/debian-10.10.0-amd64-netinst.iso"
  iso_checksum = "sha256:c433254a7c5b5b9e6a05f9e1379a0bd6ab3323f89b56537b684b6d1bd1f8b6ad"
}
```


Provisioning Finalization
-------------------------

Once the initial (Debian) installation completed - including the `ssh-server` task - the system will reboot and
allow Packer to finalize the installation via SSH, including the execution of the [provision.sh](./provision.sh) script,
to normalize the configuration of some low-level components (_grub_, _initramfs_, _fstab_, etc.) and clean things up
(such as to obtain an image as **pristine and small** as possible).

