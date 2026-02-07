#!/bin/bash
# -*- mode:bash; tab-width:2; sh-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab:
# REF: https://github.com/cedric-dufour/scriptisms/blob/master/system/packer/trixie/provision.sh
SCRIPT="${0##*/}"
VERSION='2025.09.08a'

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

  apt_modernize
    Perform 'apt modernize-sources' (convert *.list to deb822 *.sources)

  apt_disable_debsrc
    Disable 'deb-src' (Debian source packages) sources

  apt_update
    Perform 'apt-get update'

  clean_kernels
    Removed unused kernels (after the Debian installer has updated the kernel)

  clean_packages
    Remove unnecessary packages (e.g. left behind by Debian installer or non-purged packages)

  clean_ghosts
    Remove ghost packages (that do not exist in any APT repository)

  clean_orphans
    Remove orphan packages (automatically-installed packages that no manually-installed package depends upon)

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
OPT_SECTIONS=()
OPT_EXCLUDES=()
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
      shift; OPT_SECTIONS+=("${1}")
      ;;
    '-X'|'--exclude')
      [ -z "${2}" ] && echo "ERROR: Missing option parameter (${1})" >&2 && exit 1
      shift; OPT_EXCLUDES+=("${1}")
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
[ -z "${OPT_SECTIONS[*]}" ] && OPT_SECTIONS=(apt_modernize apt_disable_debsrc apt_update usrmerge clean_kernels clean_packages clean_ghosts clean_orphans preconfig_udev_ifnames preconfig_initramfs preconfig_grub preconfig_fstab preconfig_hosts apt_dist_upgrade clean_apt clean_history)


## Sections

# apt_modernize
# ?!? Weird this isn't already done by Debian/Trixie
# shellcheck disable=SC2154
DONE_apt_modernize="${PRESET_apt_modernize}"
function _apt_modernize {
  [ -n "${DONE_apt_modernize}" ] && return
  echo '============================================================================'
  echo 'BEGIN{apt_modernize}'
  apt modernize-sources --yes
  rm -f /etc/apt/sources.list.bak /etc/apt/*~ /etc/apt/sources.list.d/*~
  echo 'END{apt_modernize}'
  DONE_apt_modernize='yes'
}

# apt_disable_debsrc
# shellcheck disable=SC2154
DONE_apt_disable_debsrc="${PRESET_apt_disable_debsrc}"
function _apt_disable_debsrc {
  [ -n "${DONE_apt_disable_debsrc}" ] && return
  echo '============================================================================'
  echo 'BEGIN{apt_disable_debsrc}'
  if [ -s /etc/apt/sources.list ]; then
    sed -i -E 's/^\s*deb-src/#deb-src/' /etc/apt/sources.list
  fi
  if [ -s /etc/apt/sources.list.d/debian.sources ]; then
    echo >> /etc/apt/sources.list.d/debian.sources
    sed -nE -i /etc/apt/sources.list.d/debian.sources -f- << 'EOF'
      s/\s+$//;
      /^Types:\s*deb-src$/,/^$/{/^Enabled:/d;s/^$/Enabled: no\n/;p;b};
      /^Types:\s*(deb\s+deb-src|deb-src\s+deb)$/,/^$/{s/^Types:.*$/Types: deb/p;/^Enabled:/p;s/^Types:.*$/Types: deb-src/;/^Enabled:/d;/^$/!H;/^(Types:|Enabled:|$)/!p;/^$/{s/^$/Enabled: no\n/;H;s/^Enabled:.*$//;x;p};b};
      p
EOF
  fi
  echo 'END{apt_disable_debsrc}'
  DONE_apt_disable_debsrc='yes'
}

# apt_update
# shellcheck disable=SC2154
DONE_apt_update="${PRESET_apt_update}"
function _apt_update {
  [ -n "${DONE_apt_update}" ] && return
  echo '============================================================================'
  echo 'BEGIN{apt_update}'
  apt-get update --quiet=2
  echo 'END{apt_update}'
  DONE_apt_update='yes'
}

# usrmerge
# NB: Already installed/enabled as of Debian/Trixie but better safe than sorry
# shellcheck disable=SC2154
DONE_usrmerge="${PRESET_usrmerge}"
function _usrmerge {
  [ -n "${DONE_usrmerge}" ] && return
  _apt_update
  echo '============================================================================'
  echo 'BEGIN{usrmerge}'
  apt-get install --no-install-recommends --yes usrmerge
  echo 'END{usrmerge}'
  DONE_usrmerge='yes'
}

# clean_kernels
# shellcheck disable=SC2154
DONE_clean_kernels="${PRESET_clean_kernels}"
function _clean_kernels {
  [ -n "${DONE_clean_kernels}" ] && return
  echo '============================================================================'
  echo 'BEGIN{clean_kernels}'
  local -a debs
  readarray -tu3 debs 3< <(
    dpkg-query --show --showformat='${db:Status-Want;1} ${binary:Package}\n' 'linux-image-[0-9]*' \
    | awk '{if ($1~"[rip]") print $2}' \
    | grep -v "$(uname -r)"
  )
  [ -n "${debs[*]}" ] && apt-get autoremove --purge --yes "${debs[@]}"
  echo 'END{clean_kernels}'
  DONE_clean_kernels='yes'
}

# clean_packages
# shellcheck disable=SC2154
DONE_clean_packages="${PRESET_clean_packages}"
function _clean_packages {
  [ -n "${DONE_clean_packages}" ] && return
  echo '============================================================================'
  echo 'BEGIN{clean_packages}'
  apt-mark manual openssh-server
  local -a debs_di=(
    apt-utils debconf-i18n dictionaries-common dmidecode eject emacsen-common iamerican ibritish ienglish-common installation-report intel-microcode ispell iucode-tool laptop-detect nano ncal os-prober pci.ids pciutils perl qemu-guest-agent shared-mime-info task-english tasksel tasksel-data usrmerge util-linux-locales wamerican xauth
  )
  local -a debs_deinstall
  readarray -tu3 debs_deinstall 3< <(
    dpkg-query --show --showformat='${db:Status-Want;1} ${binary:Package}\n' \
    | awk '{if ($1~"[rp]") print $2}'
  )
  apt-get autoremove --purge --yes "${debs_di[@]}" "${debs_deinstall[@]}"
  echo 'END{clean_packages}'
  DONE_clean_packages='yes'
}

# clean_ghosts
# shellcheck disable=SC2154
DONE_clean_ghosts="${PRESET_clean_ghosts}"
function _clean_ghosts {
  [ -n "${DONE_clean_ghosts}" ] && return
  _apt_update
  echo '============================================================================'
  echo 'BEGIN{clean_ghosts}'
  for type in auto manual; do
    local -a candidates
    local -a debs
    readarray -tu3 candidates 3< <(
      apt-mark show${type} \
      | sort
    )
    readarray -tu3 debs 3< <(
      apt-cache policy "${candidates[@]}" \
      | sed -nE 's#(^(\S.*)|.*\s(https?).*)$#\2\3#p' \
      | tr -d '\n' \
      | sed -E 's#:((https?)*)#:\1\n#g' \
      | awk -F: '{if(!$2) print $1}'
    )
    if [ -n "${debs[*]}" ]; then
      echo "GHOSTS[${type}]: ${debs[*]}"
      apt-get autoremove --purge --yes "${debs[@]}"
    fi
    unset candidates debs
  done
  echo 'END{clean_ghosts}'
  DONE_clean_ghosts='yes'
}

# clean_orphans
# shellcheck disable=SC2154
DONE_clean_orphans="${PRESET_clean_orphans}"
function _clean_orphans {
  [ -n "${DONE_clean_orphans}" ] && return
  _apt_update
  echo '============================================================================'
  echo 'BEGIN{clean_orphans}'
  # NB: deborphan is no longer available in Debian/Trixie
  while true; do
    local -a depends
    local -a candidates
    local -a debs
    readarray -tu3 depends 3< <(
      apt-cache depends --installed '*' \
      | sed -nE 's#^.*Depends:\s+##p' \
      | sort -u
    )
    readarray -tu3 candidates 3< <(
      cat \
      <(apt-mark showauto '^lib.*' '.*-common$' '.*-data$' '.*-dbg$' '.*-dev$')\
      <(apt-mark showmanual '^lib.*') \
      | sort -u
    )
    readarray -tu3 debs 3< <(
      join -v1 \
      <(printf '%s\n' "${candidates[@]}") \
      <(printf '%s\n' "${depends[@]}")
    )
    [ -z "${debs[*]}" ] && break
    echo "ORPHANS: ${debs[*]}"
    apt-get autoremove --purge --yes "${debs[@]}"
    unset depends candidates debs
  done
  echo 'END{clean_orphans}'
  DONE_clean_orphans='yes'
}

# preconfig_udev_ifnames
# shellcheck disable=SC2154
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
# shellcheck disable=SC2154
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
# shellcheck disable=SC2154
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
# shellcheck disable=SC2154
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
  local device mountpoint fstype
  while read -ru3 device mountpoint fstype; do
    echo "${device} ${mountpoint} ${fstype} defaults 0 2" >> /etc/fstab
  done 3< <(
    awk '{if ($2~"^/local(/|$)") print $1, $2, $3}' /proc/mounts
  )
  echo 'END{preconfig_fstab}'
  DONE_preconfig_fstab='yes'
}

# preconfig_hosts
# shellcheck disable=SC2154
DONE_preconfig_hosts="${PRESET_preconfig_hosts}"
function _preconfig_hosts {
  [ -n "${DONE_preconfig_hosts}" ] && return
  echo '============================================================================'
  echo 'BEGIN{preconfig_hosts}'
  local hostname_fqdn hostname_short
  hostname_fqdn="$(hostname -f)"
  hostname_short="$(hostname -s)"
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
# shellcheck disable=SC2154
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
# shellcheck disable=SC2154
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
# shellcheck disable=SC2154
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
# shellcheck disable=SC2154
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
# shellcheck disable=SC2154
DONE_clean_network="${PRESET_clean_network}"
function _clean_network {
  [ -n "${DONE_clean_network}" ] && return
  echo '============================================================================'
  echo 'BEGIN{clean_network}'
  local iface
  for iface in $(ifquery --list); do
    [ "${iface}" == 'lo' ] && continue
    ifdown "${iface}"
  done
  rm -fv /var/lib/dhcp/dhclient*.leases
  echo 'END{clean_network}'
  DONE_clean_network='yes'
}

# clean_identity
# shellcheck disable=SC2154
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
# shellcheck disable=SC2154
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
# shellcheck disable=SC2154
DONE_zero_freespace="${PRESET_zero_freespace}"
function _zero_freespace {
  [ -n "${DONE_zero_freespace}" ] && return
  echo '============================================================================'
  echo 'BEGIN{zero_freespace}'
  local -a resources
  readarray -tu3 resources 3< <(awk '{if($3 ~ "^ext") print $2}' /etc/fstab)
  for resource in "${resources[@]}"; do
    if [ -z "${OPT_BATCH}" ]; then
      local prompt='yes'
      local input=
      while [ -n "${prompt}" ]; do
        echo -n "Zero free space in ${resource} [Yes/No]? " && read -r input
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
  readarray -tu3 resources 3< <(awk '{if($3 == "swap") print $1}' /etc/fstab)
  for resource in "${resources[@]}"; do
    local prompt='yes'
    local input=
    if [ -z "${OPT_BATCH}" ]; then
      while [ -n "${prompt}" ]; do
        echo -n "Zero free space in ${resource} [Yes/No]? " && read -r input
        case "${input:0:1}" in
          'Y'|'y') prompt=;;
          'N'|'n') resource=; prompt=;;
        esac
      done
    fi
    [ -z "${resource}" ] && continue
    local uuid
    uuid="$(blkid -s UUID -o value "${resource}")"
    swapoff "${resource}"
    dd if=/dev/zero of="${resource}" bs=1M
    mkswap -U "${uuid}" "${resource}"
    #swapon "${resource}"
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
for section in "${OPT_SECTIONS[@]}"; do
  echo "${OPT_EXCLUDES[*]}" | grep -qE "(^|\\s)${section}(\\s|\$)" && continue
  if [ -n "${OPT_CONFIRM}" ]; then
    prompt='yes'
    input=
    while [ -n "${prompt}" ]; do
      echo '****************************************************************************'
      echo -n "EXECUTE SECTION '${section}' [Yes/No]? " && read -r input
      case "${input:0:1}" in
        'Y'|'y') prompt=;;
        'N'|'n') continue 2;;
      esac
    done
  fi
  case "${section}" in
    'apt_modernize') _apt_modernize;;
    'apt_disable_debsrc') _apt_disable_debsrc;;
    'apt_update') _apt_update;;
    'usrmerge') _usrmerge;;
    'clean_kernels') _clean_kernels;;
    'clean_packages') _clean_packages;;
    'clean_ghosts') _clean_ghosts;;
    'clean_orphans') _clean_orphans;;
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
