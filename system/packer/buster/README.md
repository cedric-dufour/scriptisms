Creating Debian/Buster VM Image with HashiCorp Packer
=====================================================
(make sure to read the generic [README](../README.md) beforehand)

Debian Source
-------------

This sample Debian/Buster Packer-ed VM image uses the `netinst` version of the CD Installer.

To update the version being used, visit
[https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/](https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/)
to see available versions and update the [packer.json](./packer.json) file accordingly:

```json
{
  "variables": {
    "image_name": "buster",
    "image_url": "https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/debian-10.5.0-amd64-netinst.iso",
    "image_checksum": "sha256:93863e17ac24eeaa347dfb91dddac654f214c189e0379d7c28664a306e0301e7"
  }
}
```


Provisioning Finalization
-------------------------

Once the initial (Debian) installation completed - including the `ssh-server` task - the system will reboot and
allow Packer to finalize the installation via SSH, including the execution of the [provision.sh](./provision.sh) script,
to normalize the configuration of some low-level components (_grub_, _initramfs_, _fstab_, etc.) and clean things up
(such as to obtain an image as **pristine and small** as possible).

