Scripts for Engineering the Universe
====================================

Sysnopsis
---------

From delivering a new child to globally solving Earth environmental problems,
here is a collection of nifty scripts that does it all.


## Table of Contents

### 📥 [`download/`](download/) — Pinned-version installers for common CLI tools
One script per tool, each fetching and installing a specific, pinned release rather than relying on a package manager — useful for reproducible builds and CI images.

| Script | Installs |
|---|---|
| `download-clojure-tools` | Clojure CLI tools |
| `download-difftastic` | [difftastic](https://github.com/Wilfred/difftastic) structural diff tool |
| `download-exoscale-cli` | Exoscale cloud CLI |
| `download-github-cli` | GitHub CLI (`gh`) |
| `download-golang` | Go toolchain |
| `download-golangci-lint` | Go linter aggregator |
| `download-goreleaser` | Go release automation tool |
| `download-helm` | Kubernetes Helm |
| `download-jsonnet` | Jsonnet data templating language |
| `download-k9s` | Kubernetes terminal UI |
| `download-kubectl` | Kubernetes CLI |
| `download-kustomize` | Kubernetes manifest customization tool |
| `download-ovftool` | VMware OVF Tool |
| `download-packer` | HashiCorp Packer |
| `download-packer-builder-exoscale` | Exoscale builder plugin for Packer |
| `download-rclone` | Cloud storage sync tool |
| `download-restish` | REST/HTTP CLI client |
| `download-terraform` | HashiCorp Terraform |
| `download-terraform-docs` | Terraform documentation generator |
| `download-unison` | File synchronization tool |
| `download-vault` | HashiCorp Vault |
| `download-yq` | YAML/JSON/XML CLI processor |
| `download-zprint` | Clojure code formatter |

### 🧩 [`misc/`](misc/) — Standalone utilities that don't fit elsewhere
| Script | Purpose |
|---|---|
| `README.md` | Section overview |
| `ProcessTCPProxy.py` | Generic TCP proxy for process traffic inspection/redirection |
| `edoc-mailer` | Automated e-document emailing |
| **`envertec-tcp14889.py`** | Query/decode Envertech EVT microinverter local-mode data (TCP/14889) |
| `gnucash-css.scm` | Custom CSS/report styling for GnuCash |
| `gps2logbook` | Convert GPS tracks into a pilot logbook entry |
| `gpx2csv` | Convert GPX tracks to CSV |
| `gpx2flightlog` | Convert GPX tracks into SkyDemon flight logs |
| `lirc/*.conf` | IR remote configs (Acer, Denon, Feller, Netgear, Samsung) for LIRC |
| `m2requests.py` | Python HTTP client with custom SSL/cipher/engine handling |
| `markdown-rsync` | Templated rsync specifically for Markdown file trees |
| `openaip2gpx` | Convert OpenAIP aviation data to GPX |
| `pdf2html` | PDF → HTML conversion |
| `pdfxunite` | PDF merging/combination utility |
| `pseudonymize` | Data pseudonymization utility |
| `screen-split` | GNU Screen layout/splitting helper |
| `ssh-fido2-attestation.py` | FIDO2 SSH key attestation verification |
| `xctrl-easy` | X11 window/display control helper |

### 🎞️ [`multimedia/`](multimedia/) — Audio/video/image processing
| Script | Purpose |
|---|---|
| `README.md` | Section overview |
| `cinelerra-mp4cut` | Cut MP4 segments via Cinelerra |
| `imagick-downsample` | Batch image downsampling with ImageMagick |
| `lame-downsample` | Audio downsampling with LAME |
| `mplayer-streamdump` | Dump network media streams via MPlayer |

### 🖥️ [`system/`](system/) — System administration, backup, and infrastructure
The largest and most varied section — device backups, encryption, filesystem tooling, and provisioning.

**Backups & config management**
| Script | Purpose |
|---|---|
| `arubacx-backup` | Aruba CX switch config backup |
| `asuswrt-backup` / `asuswrt-restore` (+ `-v22.ini` / `-v26.1.ini`) | ASUS router firmware backup/restore |
| `fortigate-backup` | Fortinet FortiGate config backup |
| `procurve-backup` | HP ProCurve switch config backup |
| `tomato-backup` | Tomato firmware router backup |
| `gcfg-backup` | Backup via the [gcfg](https://github.com/cedric-dufour/gcfg) config-tracking tool |
| `mariadb-backup` / `mysql-backup` / `pgsql-backup` | Database dump utilities |
| `rsync-backup` / `tar-backup` / `server-backup` | General-purpose backup wrappers |
| `dircksum` | Directory checksum/integrity verification |

**Encryption & credentials**
| Script | Purpose |
|---|---|
| `encrypt-data` | Data encryption helper |
| `luksvault` / `ramvault` | LUKS-encrypted / RAM-backed vault volumes |
| `jwt-es256` | ES256 JWT signing/verification |
| `yubikey-otp-easy` / `yubikey-piv-easy` | YubiKey OTP and PIV setup helpers |
| `openssl-easy` / `openssl-peasy` | Simplified OpenSSL CA/cert workflows |
| `openssl.*.conf` | Supporting OpenSSL configs (root, server, authentication, personal, opensc-pkcs11) |

**Networking**
| Script | Purpose |
|---|---|
| `dns-make-in-addr.arpa` / `dns-make-ip6.arpa` | Generate reverse-DNS zone files (IPv4/IPv6) |
| `freedns-v2.py` (+ `.conf`) | Dynamic DNS updater |
| `huawei-3372-325-reset` / `huawei-hilink.py` (+ `.conf`) / `huawei-wctl` | Huawei USB modem/HiLink management |
| `wg-watch` | WireGuard connection monitoring |
| `riemann-query` | Query the Riemann monitoring system |

**Filesystem & storage (ZFS)**
| Script | Purpose |
|---|---|
| `zfs/drbd+zfs-io-error` | ZFS/DRBD failover on I/O error |
| `zfs/zfs-backup` | ZFS snapshot-based backup |
| `zfs/zfs-snapshot` | ZFS snapshot management |
| `zfs/zfs-mount-late.initd` (+ `.default`) | Delayed ZFS mount init script |
| `target-mount` | Mount helper for backup/restore targets |
| `ramoverlay` (+ `.service`) | RAM-backed overlay filesystem + systemd unit |

**Provisioning & builds**
| Script | Purpose |
|---|---|
| `apt-repo-easy` | Simplified local APT repository management |
| `pbuilder-easy` | Simplified Debian package build environment |
| `qemu-easy` | Simplified QEMU VM launcher |
| `makejail-ssh` | Chroot jail builder for SSH-only proxying |
| `kernel/kconfig-diff` | Diff kernel `.config` files |
| `kernel/make-kpkg-helper` | Kernel package build helper |
| `packer/` | Packer templates for Debian images: **buster, bullseye, bookworm, trixie** — each with `build.pkr.hcl`, provisioning script, and baseline/virtual-host configs, plus `debian-10..13` (likely symlinks/aliases to the codename dirs) |

**Cloud (Exoscale)**
| Script | Purpose |
|---|---|
| `exoscale/exoscale-environment` | Exoscale environment/credentials setup |
| `exoscale/exoscale-rclone-backup` (+ `.default`) | Scheduled rclone backup to Exoscale object storage |
| `exoscale/exoscale-share` | Exoscale object storage sharing helper |
| `exoscale/rclone.conf` | Supporting rclone configuration |

**Hardware & misc system**
| Script | Purpose |
|---|---|
| `enable-wakeup` | Configure Wake-on-LAN/system wakeup |
| `xps13-9380-control` | Dell XPS 13 9380 hardware control (power/fans/etc.) |

### 📄 Root
| File | Purpose |
|---|---|
| `template.bash` | Shared boilerplate/header for new Bash scripts in this repo |
