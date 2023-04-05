Creating Debian/Bookworm VM Image with HashiCorp Packer
=======================================================
(make sure to read the generic [README](../README.md) beforehand)

Debian Source
-------------

This sample Debian/Bookworm Packer-ed VM image uses the `netinst` version of the CD Installer.

To update the version being used, visit
[https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/](https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/)
to see available versions and update the [build.pkr.hcl](./build.pkr.hcl) file accordingly:

```hcl
source "qemu" "bookworm" {
  iso_url      = "https://cdimage.debian.org/cdimage/bookworm_di_rc1/amd64/iso-cd/debian-bookworm-DI-rc1-amd64-netinst.iso"
  iso_checksum = "sha256:da866b6958096e89200ba73002dd1c45bbbcde65845e129e10df6e0b03ab3884"
}
```


Provisioning Finalization
-------------------------

Once the initial (Debian) installation completed - including the `ssh-server` task - the system will reboot and
allow Packer to finalize the installation via SSH, including the execution of the [provision.sh](./provision.sh) script,
to normalize the configuration of some low-level components (_grub_, _initramfs_, _fstab_, etc.) and clean things up
(such as to obtain an image as **pristine and small** as possible).
