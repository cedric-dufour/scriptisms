Creating Debian/Trixie VM Image with HashiCorp Packer
=======================================================
(make sure to read the generic [README](../README.md) beforehand)

Debian Source
-------------

This sample Debian/Trixie Packer-ed VM image uses the `netinst` version of the CD Installer.

To update the version being used, visit
[https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/](https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/)
to see available versions and update the [build.pkr.hcl](./build.pkr.hcl) file accordingly:

```hcl
source "qemu" "bookworm" {
  iso_url      = "https://cdimage.debian.org/cdimage/trixie_di_alpha1/amd64/iso-cd/debian-trixie-DI-alpha1-amd64-netinst.iso"
  iso_checksum = "sha256:bd4a6fd7b94e6d979977437a5d4657063e978379b1934204689ed87df448ad28"
}
```


Provisioning Finalization
-------------------------

Once the initial (Debian) installation completed - including the `ssh-server` task - the system will reboot and
allow Packer to finalize the installation via SSH, including the execution of the [provision.sh](./provision.sh) script,
to normalize the configuration of some low-level components (_grub_, _initramfs_, _fstab_, etc.) and clean things up
(such as to obtain an image as **pristine and small** as possible).
