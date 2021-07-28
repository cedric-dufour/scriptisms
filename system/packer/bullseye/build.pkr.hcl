## Source
#  REF: https://www.packer.io/docs/from-1.5/blocks/source

# QEMU / KVM
# REF: https://www.packer.io/docs/builders/qemu

source "qemu" "bullseye" {
  # Image
  iso_url      = "https://cdimage.debian.org/cdimage/bullseye_di_rc2/amd64/iso-cd/debian-bullseye-DI-rc2-amd64-netinst.iso"
  iso_checksum = "sha256:6d2ec6529bfe4fd1cf65748f8b58d81085b3ae30883954227fb08d57bb44cfb9"
  # (output)
  output_directory = "${path.root}/output"
  vm_name          = "bullseye.qcow2"

  # QEMU / KVM
  qemuargs = [["-cpu", "qemu64,rdrand=on"]]
  memory   = 1024
  # (disk)
  format           = "qcow2"
  disk_image       = false
  disk_size        = 5120
  disk_compression = true

  # Communicators
  # (VNC <-> Boot)
  use_default_display = true
  boot_wait           = "5s"
  boot_command = [
    "<esc><wait5>",
    "expert<spacebar>ipv6.disable=1<spacebar>net.ifnames=0<spacebar>auto=true<spacebar>priority=critical<spacebar>url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/virtual-host.cfg<wait5>",
    "<enter>",
  ]
  # (HTTP <-> Preseeding)
  http_directory = "${path.root}/htdocs"
  http_port_min  = 8080
  http_port_max  = 8080
  # (SSH <-> Provisioner)
  communicator         = "ssh"
  ssh_username         = "root"
  ssh_private_key_file = "${path.root}/htdocs/id_ed25519"
  ssh_timeout          = "5m"

  # Shutdown
  shutdown_command = "/tmp/provision.sh --batch --section clean_shutdown"
}


## Build
#  REF: https://www.packer.io/docs/from-1.5/blocks/build
build {
  sources = ["source.qemu.bullseye"]

  ## Provisioners
  # REF: https://www.packer.io/docs/provisioners

  # File
  # REF: https://www.packer.io/docs/provisioners/file
  provisioner "file" {
    source      = "${path.root}/provision.sh"
    destination = "/tmp/"
  }

  # Shell
  # REF: https://www.packer.io/docs/provisioners/shell
  provisioner "shell" {
    inline = [
      "chmod u+x /tmp/provision.sh",
      "/tmp/provision.sh --batch",
      "/tmp/provision.sh --batch --section zero_freespace",
    ]
  }
}
