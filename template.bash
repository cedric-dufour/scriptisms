#!/bin/bash
# -*- mode:bash; tab-width:2; sh-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab:
# REF: https://github.com/cedric-dufour/scriptisms/blob/master/template.bash
set -e -o pipefail
SCRIPT="${0##*/}"
# shellcheck disable=SC2034
SCRIPT_DIR="$(dirname "$(realpath -e "${0}")")"
VERSION='0.0.19730909a'
trap 'echo "ERROR[${SCRIPT}${ARG_ACTION:+:${ARG_ACTION}}]: Internal error" >&2' ERR


## Defaults
: "${SOME_PATH:=/some/path}"


## Helpers

# Usage
__USAGE() {
  cat >&2 << EOF
USAGE: ${SCRIPT} [<options>] {sample|action|...}

SYNOPSIS:
  Bash script template

OPTIONS:

  -O, --option <type>
    Some option

  -h, --help
    Display this usage information and exit

  -v, --version
    Display this script version and exit

  --verbose, --silent
    Increase or decrease verbosity

EOF
}
[ $# -lt 1 ] && __USAGE && exit 1

# Input/Output
__INFO() {
  [ -n "${OPT_VERBOSE}" ] && echo "INFO[${SCRIPT}${ARG_ACTION:+:${ARG_ACTION}}]: ${1}"
  return 0
}

__NOTICE() {
  [ -z "${OPT_SILENT}" ] && echo "NOTICE[${SCRIPT}${ARG_ACTION:+:${ARG_ACTION}}]: ${1}"
  return 0
}

__WARNING() {
  echo "WARNING[${SCRIPT}${ARG_ACTION:+:${ARG_ACTION}}]: ${1}" >&2
  return 0
}

__ERROR() {
  echo "ERROR[${SCRIPT}${ARG_ACTION:+:${ARG_ACTION}}]: ${1}" >&2
  [ -n "${2}" ] && exit "${2}"
  return 0
}

__OPTION() {
  [ -z "${2}" ] && __ERROR "Missing option argument (${1})" 1
  return 0
}

 __CONFIRM() {
  prompt="${1}"
  options="${2}"
  [ -z "${options}" ] && options='N/y'
  IFS='/' read -r -a a_options <<< "${options}"
  while true; do
    read -r -p "CONFIRM[${SCRIPT}]: ${prompt} [${options}] ? " confirm
    if [ -z "${confirm}" ]; then
      confirm="${a_options[0]}"
    fi
    for option in "${a_options[@]}"; do
      [ "${confirm,,}" = "${option,,}" ] && echo "${option,,}" && return 0
    done
  done
}


## Arguments
OPT_OPTION=
OPT_VERBOSE="${VERBOSE}"
OPT_SILENT=
ARG_ACTION=
while [ -n "${1}" ]; do
  case "${1}" in
    '-h'|'--help')
      __USAGE; exit 0
      ;;
    '-v'|'--version')
      echo "${SCRIPT} ${VERSION}"; exit 0
      ;;
    '-O'|'--option')
      __OPTION "${@}"; OPT_OPTION="${2}"; shift
      ;;
    '--verbose')
      OPT_VERBOSE='yes'; OPT_SILENT=
      ;;
    '--silent')
      OPT_SILENT='yes'; OPT_VERBOSE=
      ;;
    -*)
      __ERROR "Invalid option (${1})" 1
      ;;
    *)
      if [ -z "${ARG_ACTION}" ]; then
        ARG_ACTION="${1}"
      else
        __ERROR "Too many arguments (${1})" 1
      fi
      ;;
  esac
  shift
done


## Checks
#[ "$(id -u)" != '0' ] && __ERROR 'This utility must be run as root (sudo)' 1


## Actions

# sample
__DO_sample() {
  __NOTICE "Sample action (option=${OPT_OPTION:-n/a})"
}


## Main
case "${ARG_ACTION}" in
  'sample')
    __DO_sample
    ;;
  *)
    __ERROR "Invalid action (${ARG_ACTION:-n/a})" 1
    ;;
esac
exit 0
