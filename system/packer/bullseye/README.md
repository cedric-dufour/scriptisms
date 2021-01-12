Creating Debian/Bullseye VM Image with HashiCorp Packer
=======================================================
(make sure to read the generic [README](../README.md) beforehand)

Debian Source
-------------

This sample Debian/Bullseye Packer-ed VM image uses the `netinst` version of the CD Installer.

To update the version being used, visit
[https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/](https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/)
to see available versions and update the [packer.json](./packer.json) file accordingly:

```json
{
  "variables": {
    "image_name": "bullseye",
    "image_url": "https://cdimage.debian.org/cdimage/bullseye_di_alpha3/amd64/iso-cd/debian-bullseye-DI-alpha3-amd64-netinst.iso",
    "image_checksum": "sha256:21e59ae4fb4ca262b184c199ca15a565ca2e17f4fb39faca9807677392852e95"
  }
}
```


Provisioning Finalization
-------------------------

Once the initial (Debian) installation completed - including the `ssh-server` task - the system will reboot and
allow Packer to finalize the installation via SSH, including the execution of the [provision.sh](./provision.sh) script,
to normalize the configuration of some low-level components (_grub_, _initramfs_, _fstab_, etc.) and clean things up
(such as to obtain an image as **pristine and small** as possible).

