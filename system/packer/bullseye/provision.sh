#!/bin/bash
# -*- mode:bash; tab-width:2; sh-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab: 
# REF: https://github.com/cedric-dufour/scriptisms/blob/master/system/packer/bullseye/provision.sh
SCRIPT="${0##*/}"
VERSION='2021.05.19a'

## Usage
function _USAGE {
  cat >&2 << EOF
USAGE: ${SCRIPT} [options]

SYSNOPSIS:
  Finalize a host provisioning after its stock/vanilla installation.

  The '-S <section>' parameter, which can be specified multiple times, allows to specific which
  specific bootstrapping section to run (all by default).

OPTIONS:

  -S, --section <section>
    Execute the given section. This option can be specified multiple times.
    Default: most sections are executed

  -X, --exclude <section>
    Exclude the given section. This option can be specified multiple times.

  -C, --confirm
    Confirm each step.

  -B, --batch
    No confirmation asked, at all; DANGEROUS!

SECTIONS:

  apt_update
    Perform 'apt-get update'

  clean_packages
    Remove unnecessary packages (e.g. left behind by Debian installer or non-purged packages)

  clean_libraries
    Remove orphan libraries (that no package depends upon)

  (clean_ghosts)
    Remove ghost packages (that do not exist in any APT repository)

  preconfig_udev_ifnames
    UDEV network interfaces naming (pre-)configuration

  preconfig_initramfs
    Update the initialization (boot) RAM filesystem

  preconfig_grub
    GRUB bootloader (pre-)configuration.

  preconfig_fstab
    Filesystem/mountpoints (pre-)configuration

  preconfig_hosts
    Hosts (name/IP) (pre-)configuration

  apt_dist_upgrade
    Perform 'apt-get dist-upgrade'

  clean_apt
    Purge APT cache (downloaded .deb files)

  clean_history
    Purge host history (logs and shell history)

  (clean_root_ssh)
    Purge 'root' user SSH directory (/root/.ssh)

  (clean_network)
    Shut all network interfaces down and clean DHCP leases

  (clean_identity)
    Reset all machine identities

  (clean_self)
    Remove this script

  (clean_shutdown)
    Shutdown host cleanly (shutting network down and purging host history)

  (zero_freespace)
    Fill local filesystem's free space with zero (such as to allow optimal compression/deduplication)

EOF
}


## Arguments
OPT_SECTIONS=
OPT_EXCLUDES=
OPT_CONFIRM=
OPT_BATCH=
while [ -n "${1}" ]; do
  case "${1}" in
    '-h'|'--help'|'help')
       _USAGE && exit 0
       ;;
    '-v'|'--version'|'version')
      echo "${SCRIPT} ${VERSION}" && exit 0
      ;;
    '-S'|'--section')
      [ -z "${2}" ] && echo "ERROR: Missing option parameter (${1})" >&2 && exit 1
      shift; OPT_SECTIONS="${OPT_SECTIONS}${OPT_SECTIONS:+ }${1}"
      ;;
    '-X'|'--exclude')
      [ -z "${2}" ] && echo "ERROR: Missing option parameter (${1})" >&2 && exit 1
      shift; OPT_EXCLUDES="${OPT_EXCLUDES}${OPT_EXCLUDES:+ }${1}"
      ;;
    '-C'|'--confirm')
      OPT_CONFIRM='yes'
      ;;
    '-B'|'--batch')
      OPT_BATCH='yes'
      ;;
    -*)
      echo "ERROR: Invalid option (${1})" >&2 && exit 1
      ;;
    *)
      echo "ERROR: Too many arguments (${1})" >&2 && exit 1
      ;;
  esac
  shift
done
[ -z "${OPT_SECTIONS}" ] && OPT_SECTIONS="apt_update clean_packages clean_libraries clean_ghosts preconfig_udev_ifnames preconfig_initramfs preconfig_grub preconfig_fstab preconfig_hosts apt_dist_upgrade clean_apt clean_history"


## Sections

# apt_update
DONE_apt_update="${PRESET_apt_update}"
function _apt_update {
  [ -n "${DONE_apt_update}" ] && return
  echo '============================================================================'
  echo 'BEGIN{apt_update}'
  apt-get update --quiet=2
  echo 'END{apt_update}'
  DONE_apt_update='yes'
}

# clean_packages
DONE_clean_packages="${PRESET_clean_packages}"
function _clean_packages {
  [ -n "${DONE_clean_packages}" ] && return
  echo '============================================================================'
  echo 'BEGIN{clean_packages}'
  apt-mark manual openssh-server
  local debs_di='apt-utils bsdextrautils bsdmainutils calendar cpp cpp-10 debconf-i18n dictionaries-common discover discover-data dmidecode eject emacsen-common gcc-9-base qemu-guest-agent iamerican ibritish ienglish-common installation-report ispell laptop-detect nano ncal os-prober pci.ids pciutils shared-mime-info task-english tasksel tasksel-data util-linux-locales wamerican xauth xdg-user-dirs'
  local debs_deinstall="$(dpkg --get-selections | grep '\sdeinstall$' | awk '{print $1}')"
  apt-get autoremove --purge --yes ${debs_di} ${debs_deinstall}
  echo 'END{clean_packages}'
  DONE_clean_packages='yes'
}

# clean_libraries
DONE_clean_libraries="${PRESET_clean_libraries}"
function _clean_libraries {
  [ -n "${DONE_clean_libraries}" ] && return
  _apt_update
  echo '============================================================================'
  echo 'BEGIN{clean_libraries}'
  debs=
  for deb in \
    $(dpkg --get-selections | grep '^lib' | awk '{print $1}' | cut -d: -f1 | sort)
  do
    [ -n "$(apt-get remove --simulate ${deb} 2>/dev/null | fgrep ' 1 to remove ')" ] && debs="${debs}${debs:+ }${deb}"
  done
  apt-get autoremove --purge --yes ${debs}
  echo 'END{clean_libraries}'
  DONE_clean_libraries='yes'
}

# clean_ghosts
DONE_clean_ghosts="${PRESET_clean_ghosts}"
function _clean_ghosts {
  [ -n "${DONE_clean_ghosts}" ] && return
  _apt_update
  echo '============================================================================'
  echo 'BEGIN{clean_ghosts}'
  apt-get autoremove --purge --yes \
    $(join -v 1 \
      <(dpkg --get-selections | awk '{print $1}' | cut -d: -f1 | sort) \
      <(for p in $(dpkg --get-selections | awk '{print $1}'); do apt-cache policy ${p}; done | egrep '(^[^ ]*:|https?://)' | egrep -B 1 'https?://' | egrep -v 'https?://' | cut -d: -f1 | sort) \
    )
  echo 'END{clean_ghosts}'
  DONE_clean_ghosts='yes'
}

# preconfig_udev_ifnames
DONE_preconfig_udev_ifnames="${PRESET_preconfig_udev_ifnames}"
function _preconfig_udev_ifnames {
  [ -n "${DONE_preconfig_udev_ifnames}" ] && return
  echo '============================================================================'
  echo 'BEGIN{preconfig_udev_ifnames}'
  cat > /etc/udev/rules.d/80-net-setup-link.rules << EOF
## File provisioned by Packer
#  (run 'update-initramfs -u -k all' to enforce changes)

# Disable consistent network device naming (stick to "eth<N>")

# Device-specific naming
# (Run 'udevadm info -a -p /sys/class/net/eth<N>' to display attributes)
#SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", KERNEL=="eth*", ATTR{address}=="<MAC-address>", ATTR{dev_id}=="0x0", ATTR{type}=="1", NAME="eth<N>"
EOF
  echo 'END{preconfig_udev_ifnames}'
  DONE_preconfig_udev_ifnames='yes'
}

# preconfig_initramfs
DONE_preconfig_initramfs="${PRESET_preconfig_initramfs}"
function _preconfig_initramfs {
  [ -n "${DONE_preconfig_initramfs}" ] && return
  echo '============================================================================'
  echo 'BEGIN{preconfig_initramfs}'
  cat > /etc/initramfs-tools/conf.d/resume << EOF
## File provisioned by Packer
#  (run 'update-initramfs -u -k all' to enforce changes)

# Disable resume (from hibernation/swap)
RESUME=none
EOF
  update-initramfs -u -k all
  echo 'END{preconfig_initramfs}'
  DONE_preconfig_initramfs='yes'
}

# preconfig_grub
DONE_preconfig_grub="${PRESET_preconfig_grub}"
function _preconfig_grub {
  [ -n "${DONE_preconfig_grub}" ] && return
  echo '============================================================================'
  echo 'BEGIN{preconfig_grub}'
  cat > /etc/default/grub << EOF
## File provisioned by Packer
#  (run 'update-grub' to enforce changes)

# Bootloader settings
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1"
GRUB_DISABLE_SUBMENU=y
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR=\`lsb_release -i -s 2> /dev/null || echo Debian\`
GRUB_CMDLINE_LINUX_DEFAULT="quiet"
GRUB_CMDLINE_LINUX="spinlock=unfair clocksource=hpet console=ttyS0"
EOF
  update-grub
  echo 'END{preconfig_grub}'
  DONE_preconfig_grub='yes'
}

# preconfig_fstab
DONE_preconfig_fstab="${PRESET_preconfig_fstab}"
function _preconfig_fstab {
  [ -n "${DONE_preconfig_fstab}" ] && return
  echo '============================================================================'
  echo 'BEGIN{preconfig_fstab}'
  cat > /etc/fstab << EOF
## File provisioned by Packer
#  <file system> <mount point> <type> <options> <dump> <pass>

# System
EOF
  # / (root)
  local root
  root="$(df --output=source,target,fstype / | sed '/^Filesystem/d;s/  */ /g')"
  [ -n "${root}" ] && echo "${root} errors=remount-ro 0 1" >> /etc/fstab
  # /boot
  local part
  part="$(df --output=source /boot/ 2>/dev/null | sed '/^Filesystem/d')"
  if [ "${part}" != "${root}" ]; then
    [[ "${part:0:7}" =~ ^/dev/[sm]d$ ]] && part="UUID=$(blkid -s UUID -o value "${part}")"
    echo "${part} $(df --output=target,fstype /boot/ | sed '/^Mounted/d;s/  */ /g') defaults 0 2" >> /etc/fstab
  fi
  # /boot/efi
  part="$(df --output=source /boot/efi/ 2>/dev/null | sed '/^Filesystem/d')"
  if [ -n "${part}" ]; then
    [[ "${part:0:7}" =~ ^/dev/[sm]d$ ]] && part="UUID=$(blkid -s UUID -o value "${part}")"
    echo "${part} $(df --output=target,fstype /boot/efi/ | sed '/^Mounted/d;s/  */ /g') umask=0077 0 1" >> /etc/fstab
  fi
  # /tmp
  part="$(df --output=source,target,fstype /tmp/ | sed '/^Filesystem/d;s/  */ /g')"
  [ "${part}" != "${root}" ] && echo "${part} defaults 0 2" >> /etc/fstab
  # /var
  part="$(df --output=source,target,fstype /var/ | sed '/^Filesystem/d;s/  */ /g')"
  [ "${part}" != "${root}" ] && echo "${part} defaults 0 2" >> /etc/fstab
  # /usr
  part="$(df --output=source,target,fstype /usr/ | sed '/^Filesystem/d;s/  */ /g')"
  [ "${part}" != "${root}" ] && echo "${part} defaults 0 2" >> /etc/fstab
  # /home
  part="$(df --output=source,target,fstype /home/ | sed '/^Filesystem/d;s/  */ /g')"
  [ "${part}" != "${root}" ] && echo "${part} defaults 0 2" >> /etc/fstab
  # swap
  part="$(blkid -l -t TYPE=swap -o device)"
  [ -n "${part}" ] && echo "${part} none swap sw 0 0" >> /etc/fstab
  cat >> /etc/fstab << EOF

# Data
# (add additional non-system partitions below)
# - local: /dev/<dev> /local/data ext4 defaults 0 2
# - NFS: <server>:<export> /remote/data nfs tcp,vers=3,rw,hard 0 0
EOF
  local device_mountpoint_fstype; for device_mountpoint_fstype in $(grep -E '\s/local(\s|/)' /proc/mounts | awk '{print $1":"$3":"$5}'); do
    device="${device_mountpoint_fstype##:*}"; device_mountpoint_fstype="${device_mountpoint_fstype%*:}"
    mountpoint="${device_mountpoint_fstype##:*}"; device_mountpoint_fstype="${device_mountpoint_fstype%*:}"
    fstype="${device_mountpoint_fstype}"
    echo "${device} ${mountpoint} ${fstype} defaults 0 2" >> /etc/fstab
  done
  echo 'END{preconfig_fstab}'
  DONE_preconfig_fstab='yes'
}

# preconfig_hosts
DONE_preconfig_hosts="${PRESET_preconfig_hosts}"
function _preconfig_hosts {
  [ -n "${DONE_preconfig_hosts}" ] && return
  echo '============================================================================'
  echo 'BEGIN{preconfig_hosts}'
  local hostname_fqdn="$(hostname -f)"
  local hostname_short="$(hostname -s)"
  cat > /etc/hosts << EOF
## File provisioned by Packer

# IPv4
127.0.0.1 localhost
127.0.1.1 ${hostname_fqdn} ${hostname_short} lanhost

# IPv6
::1 localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
#IPv6: ${hostname_fqdn} ${hostname_short} ip6-lanhost
EOF
  echo 'END{preconfig_hosts}'
  DONE_preconfig_hosts='yes'
}

# apt_dist_upgrade
DONE_apt_dist_upgrade="${PRESET_apt_dist_upgrade}"
function _apt_dist_upgrade {
  [ -n "${DONE_apt_dist_upgrade}" ] && return
  _apt_update
  echo '============================================================================'
  echo 'BEGIN{apt_dist_upgrade}'
  apt-get dist-upgrade --yes --no-install-recommends --allow-unauthenticated
  apt-get autoremove --purge --yes
  echo 'END{apt_dist_upgrade}'
  DONE_apt_dist_upgrade='yes'
}

# clean_apt
DONE_clean_apt="${PRESET_clean_apt}"
function _clean_apt {
  [ -n "${DONE_clean_apt}" ] && return
  echo '============================================================================'
  echo 'BEGIN{clean_apt}'
  apt-get clean
  echo 'END{clean_apt}'
  DONE_clean_apt='yes'
}

# clean_history
DONE_clean_history="${PRESET_clean_history}"
function _clean_history {
  [ -n "${DONE_clean_history}" ] && return
  echo '============================================================================'
  echo 'BEGIN{clean_history}'
  find /var/log -type f \( \
    -name "debug" -o \
    -name "messages" -o \
    -name "*log" -o \
    -name "*.gz" -o \
    -name "*.xz" -o \
    -name "*[-_.][0-9]*" -o \
    -name "*.notice" -o \
    -name "*.info" -o \
    -name "*.warn" -o \
    -name "*.err" -o \
    -name "*.crit" \
  \) -exec rm -fv {} \;
  rm -fv /root/.bash_history
  echo 'PLEASE CLEAR SHELL HISTORY MANUALLY (history -c)!'
  echo 'END{clean_history}'
  DONE_clean_history='yes'
}

# clean_root_ssh
DONE_clean_root_ssh="${PRESET_clean_root_ssh}"
function _clean_root_ssh {
  [ -n "${DONE_clean_root_ssh}" ] && return
  echo '============================================================================'
  echo 'BEGIN{clean_root_ssh}'
  rm -rfv /root/.ssh
  echo 'END{clean_root_ssh}'
  DONE_clean_root_ssh='yes'
}

# clean_network
DONE_clean_network="${PRESET_clean_network}"
function _clean_network {
  [ -n "${DONE_clean_network}" ] && return
  echo '============================================================================'
  echo 'BEGIN{clean_network}'
  local iface
  for iface in $(ifquery --list); do
    [ "${iface}" == 'lo' ] && continue
    ifdown ${iface}
  done
  rm -fv /var/lib/dhcp/dhclient*.leases
  echo 'END{clean_network}'
  DONE_clean_network='yes'
}

# clean_identity
DONE_clean_identity="${PRESET_clean_identity}"
function _clean_identity {
  [ -n "${DONE_clean_identity}" ] && return
  echo '============================================================================'
  echo 'BEGIN{clean_identity}'
  # reset machine-id
  # REF: https://www.man7.org/linux/man-pages/man5/machine-id.5.html#FIRST_BOOT_SEMANTICS
  echo 'uninitialized' | tee /etc/machine-id
  # REF: https://wiki.debian.org/MachineId
  rm -fv /var/lib/dbus/machine-id
  ln -s /etc/machine-id /var/lib/dbus/machine-id
  echo 'END{clean_identity}'
  DONE_clean_identity='yes'
}

# clean_self
DONE_clean_self="${PRESET_clean_self}"
function _clean_self {
  [ -n "${DONE_clean_self}" ] && return
  echo '============================================================================'
  echo 'BEGIN{clean_self}'
  rm -fv "${0}"
  echo 'END{clean_self}'
  DONE_clean_self='yes'
}

# clean_shutdown
function _clean_shutdown {
  _clean_apt
  _clean_history
  _clean_root_ssh
  _clean_network
  _clean_identity
  _clean_self
  echo '============================================================================'
  echo 'BEGIN{clean_shutdown}'
  shutdown --poweroff now
  echo 'END{clean_shutdown}'
}

# zero_freespace
DONE_zero_freespace="${PRESET_zero_freespace}"
function _zero_freespace {
  [ -n "${DONE_zero_freespace}" ] && return
  echo '============================================================================'
  echo 'BEGIN{zero_freespace}'
  local resource
  for resource in $(awk '{if($3 ~ "^ext") print $2}' /etc/fstab); do
    if [ -z "${OPT_BATCH}" ]; then
      local prompt='yes'
      local input=
      while [ -n "${prompt}" ]; do
        echo -n "Zero free space in ${resource} [Yes/No]? " && read input
        case "${input:0:1}" in
          'Y'|'y') prompt=;;
          'N'|'n') resource=; prompt=;;
        esac
      done
    fi
    [ -z "${resource}" ] && continue
    dd if=/dev/zero of="${resource%%/}/ZERO" bs=1M
    rm "${resource%%/}/ZERO"
  done
  for resource in $(awk '{if($3 ~ "^swap$") print $1}' /etc/fstab); do
    local prompt='yes'
    local input=
    if [ -z "${OPT_BATCH}" ]; then
      while [ -n "${prompt}" ]; do
        echo -n "Zero free space in ${resource} [Yes/No]? " && read input
        case "${input:0:1}" in
          'Y'|'y') prompt=;;
          'N'|'n') resource=; prompt=;;
        esac
      done
    fi
    [ -z "${resource}" ] && continue
    local uuid="$(blkid -s UUID -o value "${resource}")"
    swapoff "${resource}"
    dd if=/dev/zero of="${resource}" bs=1M
    mkswap -U "${uuid}" "${resource}"
    swapon "${resource}"
  done
  echo 'END{zero_freespace}'
  DONE_zero_freespace='yes'
}


## Main

# Disable DPKG popups
if [ -n "${OPT_CONFIRM}" ]; then
  export DEBIAN_FRONTEND=dialog
  export DEBIAN_PRIORITY=high
else
  export DEBIAN_FRONTEND=noninteractive
  export DEBIAN_PRIORITY=critical
fi

# Loop through sections
for section in ${OPT_SECTIONS}; do
  [ -n "$(echo ${OPT_EXCLUDES} | egrep "(^|\\s)${section}(\\s|\$)")" ] && continue
  if [ -n "${OPT_CONFIRM}" ]; then
    prompt='yes'
    input=
    while [ -n "${prompt}" ]; do
      echo '****************************************************************************'
      echo -n "EXECUTE SECTION '${section}' [Yes/No]? " && read input
      case "${input:0:1}" in
        'Y'|'y') prompt=;;
        'N'|'n') continue 2;;
      esac
    done
  fi
  case "${section}" in
    'apt_update') _apt_update;;
    'clean_packages') _clean_packages;;
    'clean_libraries') _clean_libraries;;
    'clean_ghosts') _clean_ghosts;;
    'preconfig_udev_ifnames') _preconfig_udev_ifnames;;
    'preconfig_initramfs') _preconfig_initramfs;;
    'preconfig_grub') _preconfig_grub;;
    'preconfig_fstab') _preconfig_fstab;;
    'preconfig_hosts') _preconfig_hosts;;
    'apt_dist_upgrade') _apt_dist_upgrade;;
    'clean_apt') _clean_apt;;
    'clean_history') _clean_history;;
    'clean_root_ssh') _clean_root_ssh;;
    'clean_network') _clean_network;;
    'clean_identity') _clean_identity;;
    'clean_self') _clean_self;;
    'clean_shutdown') _clean_shutdown;;
    'zero_freespace') _zero_freespace;;
    *) echo "ERROR: Invalid section (${section})" >&2 && exit 1;;
  esac
done
