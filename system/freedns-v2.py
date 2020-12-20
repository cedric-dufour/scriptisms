#!/usr/bin/env python3
# -*- mode:python; tab-width:4; c-basic-offset:4; intent-tabs-mode:nil; -*-
# ex: filetype=python tabstop=4 softtabstop=4 shiftwidth=4 expandtab autoindent smartindent

# ------------------------------------------------------------------------------
# DEPENDENCIES
# ------------------------------------------------------------------------------

# Standard
import argparse
import errno
import logging
from logging.handlers import SysLogHandler
import os
import os.path
import re
import signal
import subprocess
import sys
import time
from urllib.parse import urlencode

# External
# ... deb: python3-daemon, python3-requests, python3-toml
from daemon import DaemonContext
from daemon.runner import emit_message, is_pidfile_stale, make_pidlockfile
import requests
import toml


# Logging
logger = logging.getLogger("FreeDNSv2")


# ------------------------------------------------------------------------------
# CONSTANTS
# ------------------------------------------------------------------------------

FREEDNS_V2_VERSION = "2020.12.20a"

FREEDNS_V2_URL_IPV4 = "%{scheme}://sync.afraid.org/u/%{token}/"
FREEDNS_V2_URL_IPV6 = "%{scheme}://v6.sync.afraid.org/u/%{token}/"
FREEDNS_V2_ARG_ADDRESS = "address"

FREEDNS_V2_RE_UPDATED = "^Updated .* from ([.:0-9a-f]+) to ([.:0-9a-f]+).*$"
FREEDNS_V2_RE_UNCHANGED = "^No IP change .* IP ([.:0-9a-f]+).*$"

FREEDNS_V2_CONFIG = {
    "ssl": True,
    "token": None,
    "quiet": False,
    "debug": False,
    "address": {
        "ipv6": False,
        "check": None,
    },
    "period": {
        "loop": 3600,
        "force": 0,
    },
}


# ------------------------------------------------------------------------------
# CLASSES
# ------------------------------------------------------------------------------


class FreeDNSv2_Config:
    def merge(base: dict, overwrite: dict):
        merged = {}
        for key, value in base.items():
            value = overwrite.get(key, value)
            if isinstance(value, dict):
                if key in overwrite:
                    value = FreeDNSv2_Config.merge(base[key], overwrite[key])
                else:
                    value = value.copy()
            if isinstance(value, str) and value.startswith("~/"):
                value = os.path.expanduser(value)
            merged[key] = value

        return merged

    def load(path):
        config = FREEDNS_V2_CONFIG

        logger.debug(f"Config:load: Loading/merging configuration from {path}")

        config = FreeDNSv2_Config.merge(config, toml.load(path))

        logger.debug(f"Config:load: {config}")

        return config


class FreeDNSv2:
    """
    FreeDNS Updater Client (V2 interface)
    """

    # ------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    # ------------------------------------------------------------------------------

    def __init__(self):
        """
        Constructor.
        """

        # Fields
        # ... configuration
        self.__oArgumentParser = None
        self.__oArguments = None
        self.__dConfig = None

        # ... runtime
        self.__iPID = os.getpid()
        self.__bStop = False
        self.__bQuiet = False
        self.__bDebug = False
        self.__bDryRun = False

        # Initialization
        self.__initArgumentParser()

    def __initArgumentParser(self):
        """
        Creates the arguments parser (and help generator).
        """

        # Create argument parser
        self.__oArgumentParser = argparse.ArgumentParser(sys.argv[0].split(os.sep)[-1])

        # ... configuration file
        self.__oArgumentParser.add_argument(
            "-c",
            "--config",
            type=str,
            metavar="<conf-file>",
            default="/etc/freedns.conf",
            help="Path to configuration file (default:/etc/freedns.conf)",
        )

        # ... PID file
        self.__oArgumentParser.add_argument(
            "-p",
            "--pid",
            type=str,
            metavar="<pid-file>",
            default="/var/run/freedns.pid",
            help="Path to daemon PID file (default:/var/run/freedns.pid)",
        )

        # ... remain in foreground
        self.__oArgumentParser.add_argument(
            "-f",
            "--foreground",
            action="store_true",
            default=False,
            help="Do not fork to background / Remain on foreground",
        )

        # ... quiet
        self.__oArgumentParser.add_argument(
            "-q",
            "--quiet",
            action="store_true",
            default=False,
            help="Output only error messages",
        )

        # ... debug
        self.__oArgumentParser.add_argument(
            "-d",
            "--debug",
            action="store_true",
            default=False,
            help="Output debugging messages",
        )

        # ... dry-run
        self.__oArgumentParser.add_argument(
            "--dry-run",
            action="store_true",
            default=False,
            help="Dry run (do not perform actual update)",
        )

        # ... version
        self.__oArgumentParser.add_argument(
            "-v",
            "--version",
            action="version",
            version=(
                f"freedns-v2 - {FREEDNS_V2_VERSION} - Cedric Dufour <http://cedric.dufour.name>\n"
            ),
        )

    # ------------------------------------------------------------------------------
    # METHODS
    # ------------------------------------------------------------------------------

    #
    # Daemon
    #

    def __signal(self, signal, frame):
        self.stop()

    def __daemon(self):
        """
        Daemonizes the process; returns a non-zero exit code in case of failure.
        """

        # Daemonize
        try:
            # Create and check PID file
            oPidLockFile = make_pidlockfile(self.__oArguments.pid, 0)
            if is_pidfile_stale(oPidLockFile):
                oPidLockFile.break_lock()
            if oPidLockFile.is_locked():
                iPid = oPidLockFile.read_pid()
                logger.error(f"daemon: Process already running; PID={iPid}")
                return errno.EEXIST

            # Create daemon context
            oDaemonContext = DaemonContext(pidfile=oPidLockFile)
            oDaemonContext.signal_map = {signal.SIGTERM: self.__signal}
            oDaemonContext.open()
            emit_message(f"daemon: Forked to background; PID={os.getpid()}")

            # Redirect standard error to syslog
            oHandler = SysLogHandler(address="/dev/log")
            oHandler.setLevel(logger.level)
            oHandler.setFormatter(
                logging.Formatter("%(name)s[%(process)d]: %(levelname)s: %(message)s")
            )
            logger.addHandler(oHandler)

            # Execute
            return self.__updater()
        except Exception as e:
            logger.error(f"daemon: Failed to fork to background; {str(e)}")
            return errno.ESRCH

    #
    # Updater
    #

    def __updater(self):
        """
        FreeDNS updater routine (loop).
        """

        # Build update URI
        sURI = (
            FREEDNS_V2_URL_IPV6
            if self.__dConfig["address"]["ipv6"]
            else FREEDNS_V2_URL_IPV4
        )
        sURI = sURI.replace("%{scheme}", "https" if self.__dConfig["ssl"] else "http")
        sURI = sURI.replace("%{token}", self.__dConfig["token"])

        # Build response parsers
        reUpdated = re.compile(FREEDNS_V2_RE_UPDATED)
        reUnchanged = re.compile(FREEDNS_V2_RE_UNCHANGED)

        # Updater loop
        iErrNo = 0
        fTime_last = 0.0
        fTime_lastUpdate = 0.0
        sExternalAddress = None
        while True:
            # Stop
            if self.__bStop:
                break

            # Sleep
            fTime_now = time.time()
            if self.__dConfig["period"]["loop"] > 0:
                if fTime_now - fTime_last <= self.__dConfig["period"]["loop"]:
                    time.sleep(1)
                    continue
            else:
                if fTime_last > 0.0:
                    break
            fTime_last = fTime_now

            # Loop-local variables
            sExternalAddress_new = None
            sURI_query = {}

            # Check external IP address
            if self.__dConfig["address"]["check"] is not None:

                # Execute checker script
                try:
                    oExternalAddress = subprocess.run(
                        args=self.__dConfig["address"]["check"],
                        shell=True,
                        capture_output=True,
                        check=True,
                        timeout=10,
                    )
                    sExternalAddress_new = oExternalAddress.stdout.decode(
                        sys.stdout.encoding
                    ).strip()
                except Exception as e:
                    logger.error(f"checker: Failed to retrieve IP address; {str(e)}")
                    iErrNo = oExternalAddress.returncode
                    break

                # Check output
                if len(sExternalAddress_new):
                    sURI_query[FREEDNS_V2_ARG_ADDRESS] = sExternalAddress_new
                    if sExternalAddress_new != sExternalAddress:
                        logger.info(
                            f"checker: IP address changed; {sExternalAddress} -> {sExternalAddress_new}"
                        )
                    else:
                        logger.debug(
                            f"checker: IP address unchanged; {sExternalAddress_new}"
                        )
                        if (
                            self.__dConfig["period"]["force"] > 0
                            and fTime_now - fTime_lastUpdate
                            >= self.__dConfig["period"]["force"]
                        ):
                            logger.debug("checker: Forcefully updating...")
                        else:
                            continue
                else:
                    logger.warning("checker: Script returned no IP address")
                    continue

            # Update
            try:
                # Query string
                if len(sURI_query):
                    sURI_update = "{}?{}".format(sURI, urlencode(sURI_query))
                else:
                    sURI_update = sURI

                # HTTP request
                if not self.__bDryRun:
                    oResponse = requests.get(sURI_update)
                    oResponse.raise_for_status()
                    sResponse = oResponse.text
                else:
                    sResponse = "Dry-run mode (no FreeDNS response to parse)"

                # Parse IP address from response
                oMatch = reUpdated.match(sResponse)
                if oMatch:
                    sExternalAddress = oMatch.group(2)
                    logger.info(
                        f"updater: IP address updated; {oMatch.group(1)} -> {sExternalAddress}"
                    )
                else:
                    oMatch = reUnchanged.match(sResponse)
                    if oMatch:
                        sExternalAddress = oMatch.group(1)
                        logger.info(
                            f"updater: IP address unchanged; {sExternalAddress}"
                        )
                    else:
                        sExternalAddress = "N/A"
                        logger.warning(
                            f"updater: Failed to parse IP address out of FreeDNS response; {sResponse}"
                        )

                # Loop-global variables update
                fTime_lastUpdate = fTime_now
                sExternalAddress = sExternalAddress_new
            except Exception as e:
                logger.warning(f"updater: Failed to update IP address; {str(e)}")

        return iErrNo

    #
    # Main
    #

    def run(self):
        """
        Run the daemon; returns a non-zero exit code in case of failure.
        """

        # Initialize

        # ... arguments
        try:
            self.__oArguments = self.__oArgumentParser.parse_args()
        except Exception as e:
            logger.error(f"run: Failed to parse arguments; {str(e)}")
            return errno.EINVAL
        self.__bDryRun = self.__oArguments.dry_run
        self.__bDebug = self.__bDryRun or self.__oArguments.debug

        # ... verbosity
        if self.__bDebug:
            logger.setLevel(logging.DEBUG)

        # ... configuration
        try:
            self.__dConfig = FreeDNSv2_Config.load(self.__oArguments.config)
        except Exception as e:
            logger.error(f"run: Failed to load configuration; {str(e)}")
            return errno.EINVAL
        if self.__dConfig["token"] is None:
            logger.error("run: Please specify the FreeDNS subdomain token")
            return errno.EINVAL
        self.__bDebug = self.__bDebug or self.__dConfig["debug"]
        self.__bQuiet = self.__oArguments.quiet or self.__dConfig["quiet"]

        # Verbosity
        if self.__bDebug:
            logger.setLevel(logging.DEBUG)
        elif self.__bQuiet:
            logger.setLevel(logging.WARNING)
        else:
            logger.setLevel(logging.INFO)

        # Fork to background (?)
        if not self.__oArguments.foreground:
            logger.debug("run: Starting background daemon")
            return self.__daemon()

        # Foreground processing
        logger.debug("run: Starting foreground processing")
        signal.signal(signal.SIGINT, self.__signal)
        signal.signal(signal.SIGTERM, self.__signal)
        return self.__updater()

    def stop(self):
        """
        Stop the daemon and exit gracefully.
        """

        logger.info("stop: Signal received; stopping...")
        self.__bStop = True


# ------------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        logging.basicConfig()
        sys.exit(FreeDNSv2().run())
    except KeyboardInterrupt:
        sys.exit(-2)
