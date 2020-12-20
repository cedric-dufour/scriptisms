#!/usr/bin/env python3
# -*- mode:python; tab-width:4; c-basic-offset:4; intent-tabs-mode:nil; -*-
# ex: filetype=python tabstop=4 softtabstop=4 shiftwidth=4 expandtab autoindent smartindent

# ------------------------------------------------------------------------------
# DEPENDENCIES
# ------------------------------------------------------------------------------

# Standard
import argparse
import errno
import json
import logging
import os
import sys

# External
# ... deb: python3-huawei-lte-api (https://repository.salamek.cz/), python3-toml
from huawei_lte_api.AuthorizedConnection import AuthorizedConnection
from huawei_lte_api.Connection import Connection
import toml


# Logging
logger = logging.getLogger("HuaweiHilink")


# ------------------------------------------------------------------------------
# CONSTANTS
# ------------------------------------------------------------------------------

HUAWEI_HILINK_VERSION = "2020.12.20a"

HUAWEI_HILINK_CONFIG = {
    "endpoint": "192.168.8.1",
    "ssl": False,
    "username": "admin",
    "password": "",
    "pin": "",
}

HUAWEI_HILINK_API = {
    # REF: https://github.com/Salamek/huawei-lte-api/blob/master/huawei_lte_api/api/Device.py
    "device": {
        "class": "Device",
        "commands": {
            # Getters
            "get-antenna-status": {
                "method": "antenna_status",
            },
            "get-antenna-type": {
                "method": "antenna_type",
            },
            "get-information": {
                "method": "information",
            },
            "get-signal": {
                "method": "signal",
            },
            # Setters
            "set-antenna-type": {
                "method": "antenna_set_type",
            },
            # Actions
            "reboot": {
                "method": "reboot",
            },
        },
    },
    # REF: https://github.com/Salamek/huawei-lte-api/blob/master/huawei_lte_api/api/Diagnosis.py
    "diagnosis": {
        "class": "Diagnosis",
        "commands": {
            # Getters
            "get-ping": {
                "method": "diagnose_ping",
            },
            "get-traceroute": {
                "method": "diagnose_traceroute",
            },
            "get-traceroute-result": {
                "method": "trace_route_result",
            },
            # Setters
            # Actions
            "ping": {
                "method": "set_diagnose_ping",
                "uargs": {"host": "host", "timeout": "timeout"},
            },
            "traceroute": {
                "method": "set_diagnose_traceroute",
                "uargs": {"host": "host", "timeout": "timeout"},
            },
        },
    },
    # REF: https://github.com/Salamek/huawei-lte-api/blob/master/huawei_lte_api/api/DialUp.py
    "dialup": {
        "class": "DialUp",
        "commands": {
            # Getters
            "get-connection": {
                "method": "connection",
            },
            "get-mobiledata-switch": {
                "method": "mobile_dataswitch",
                "help": "Get current LTE modem state",
            },
            "get-profiles": {
                "method": "profiles",
            },
            # Setters
            "set-mobiledata-switch": {
                "method": "set_mobile_dataswitch",
                "uargs": {"dataswitch": "state"},
                "help": "Set LTE modem state",
            },
            # Actions
            "connect": {
                "method": "dial",
            },
        },
    },
    # REF: https://github.com/Salamek/huawei-lte-api/blob/master/huawei_lte_api/api/Monitoring.py
    "monitoring": {
        "class": "Monitoring",
        "commands": {
            # Getters
            "get-start-date": {
                "method": "start_date",
            },
            "get-statistics": {
                "method": "traffic_statistics",
            },
            "get-statistics-month": {
                "method": "month_statistics",
            },
            "get-status": {
                "method": "status",
            },
            # Setters
            "set-start-date": {
                "method": "set_start_date",
                "uargs": {
                    "start_day": "day",
                    "data_limit": "data",
                    "month_threshold": "percent",
                },
            },
            # Actions
            "clear-statistics": {
                "method": "set_clear_traffic",
            },
        },
    },
    # REF: https://github.com/Salamek/huawei-lte-api/blob/master/huawei_lte_api/api/Net.py
    "net": {
        "class": "Net",
        "commands": {
            # Getters
            "get-cell": {
                "method": "cell_info",
            },
            "get-csps": {
                "method": "csps_state",
            },
            "get-mode": {
                "method": "net_mode",
            },
            "get-mode-list": {
                "method": "net_mode_list",
            },
            "get-network": {
                "method": "current_plmn",
            },
            "get-network-list": {
                "method": "plmn_list",
                "help": "WARNING: Disconnects from the network!",
            },
            "get-register": {
                "method": "register",
            },
            # Actions
            "register-auto": {
                "method": "set_register",
                "sargs": {"mode": "0", "plmn": "", "rat": ""},
            },
            "register": {
                "method": "set_register",
                "sargs": {"mode": "1", "rat": ""},
                "uargs": {"plmn": "id"},
            },
        },
    },
    # REF: https://github.com/Salamek/huawei-lte-api/blob/master/huawei_lte_api/api/Pin.py
    "pin": {
        "class": "Pin",
        "commands": {
            # Getters
            "get-save-pin": {
                "method": "save_pin",
            },
            "get-simlock": {
                "method": "simlock",
            },
            "get-status": {
                "method": "status",
            },
            # Actions
            "disable": {
                "method": "operate",
                "sargs": {"operate_type": 2},
                "uargs": {"current_pin": "pin"},
            },
            "enable": {
                "method": "operate",
                "sargs": {"operate_type": 1},
                "uargs": {"current_pin": "pin"},
            },
            "verify": {
                "method": "operate",
                "sargs": {"operate_type": 0},
                "uargs": {"current_pin": "pin"},
            },
        },
    },
    # REF: https://github.com/Salamek/huawei-lte-api/blob/master/huawei_lte_api/api/Sms.py
    "sms": {
        "class": "Sms",
        "commands": {
            # Getters
            "get-count": {
                "method": "sms_count",
            },
            "get-list": {
                "method": "get_sms_list",
                "sargs": {"read_count": 20},
                "uargs": {"page": "page"},
            },
            "get-send-status": {
                "method": "send_status",
            },
            # Actions
            "cancel": {
                "method": "cancel_send",
            },
            "delete": {
                "method": "delete_sms",
                "uargs": {"sms_id": "id"},
            },
            "read": {
                "method": "set_read",
                "uargs": {"sms_id": "id"},
            },
            "send": {
                "method": "send_sms",
                "uargs": {"message": "text", "phone_numbers": "recipient"},
            },
        },
    },
    # REF: https://github.com/Salamek/huawei-lte-api/blob/master/huawei_lte_api/api/Syslog.py
    "syslog": {
        "class": "Syslog",
        "commands": {
            # Getters
            "get-logs": {
                "method": "querylog",
            },
            # Actions
            "clear-logs": {
                "method": "clear",
            },
        },
    },
}


# ------------------------------------------------------------------------------
# CLASSES
# ------------------------------------------------------------------------------


class HuaweiHilink_Config:
    def merge(base: dict, overwrite: dict):
        merged = {}
        for key, value in base.items():
            value = overwrite.get(key, value)
            if isinstance(value, dict):
                if key in overwrite:
                    value = HuaweiHilink_Config.merge(base[key], overwrite[key])
                else:
                    value = value.copy()
            if isinstance(value, str) and value.startswith("~/"):
                value = os.path.expanduser(value)
            merged[key] = value

        return merged

    def load(path: str = None):
        config = HUAWEI_HILINK_CONFIG

        if path is not None:
            logger.debug(f"Config:load: Loading/merging configuration from {path}")
            config = HuaweiHilink_Config.merge(config, toml.load(path))
        else:
            # WARNING: Although TOML allows loading from multiple files at once, it does
            # so by performing a *shallow* merge (when we'd rather have a *deep* merge)
            for path in (
                "/etc/huawei-hilink.conf",
                os.path.expanduser("~/.config/huawei-hilink.conf"),
            ):
                if not os.path.isfile(path):
                    continue
                logger.debug(f"Config:load: Loading/merging configuration from {path}")
                config = HuaweiHilink_Config.merge(config, toml.load(path))

        logger.debug(f"Config:load: {config}")

        return config


class HuaweiHilink:
    """
    Huawei Hilink command-line client
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

        # Initialization
        self.__initArgumentParser()

    def __initArgumentParser(self):
        """
        Creates the arguments parser (and help generator).
        """

        # Create argument parser
        self.__oArgumentParser = argparse.ArgumentParser(sys.argv[0].split(os.sep)[-1])

        # ... category
        self.__oArgumentParser.add_argument(
            "category",
            type=str,
            choices=HUAWEI_HILINK_API.keys(),
            help="Command category",
        )

        # ... command
        self.__oArgumentParser.add_argument(
            "command",
            type=str,
            nargs="?",
            default="help",
            help="Command (use 'help' to obtain the list of commands for the given category)",
        )

        # ... configuration file
        self.__oArgumentParser.add_argument(
            "-c",
            "--config",
            type=str,
            metavar="<conf-file>",
            help="Path to specific configuration file (default: /etc/huawei-hilink.conf + ~/.config/huawei-hilink.conf)",
        )

        # ... output field
        self.__oArgumentParser.add_argument(
            "-f",
            "--field",
            type=str,
            metavar="<name>",
            help="Output given field (instead of full JSON)",
        )

        # ... debug
        self.__oArgumentParser.add_argument(
            "-d",
            "--debug",
            action="store_true",
            default=False,
            help="Output debugging messages",
        )

        # ... version
        self.__oArgumentParser.add_argument(
            "-v",
            "--version",
            action="version",
            version=(
                f"huawei-hilink - {HUAWEI_HILINK_VERSION} - Cedric Dufour <http://cedric.dufour.name>\n"
            ),
        )

        # API arguments

        # ... data
        self.__oArgumentParser.add_argument(
            "--data",
            type=str,
            metavar="<str>",
            help="Data (quantity; e.g. 1000MB or 1GB)",
        )

        # ... day
        self.__oArgumentParser.add_argument(
            "--day",
            type=int,
            metavar="<int>",
            default=1,
            help="Day of month (default: 1)",
        )

        # ... host
        self.__oArgumentParser.add_argument(
            "--host",
            type=str,
            metavar="<str>",
            default="localhost",
            help="Host name or IP address (default: localhost)",
        )

        # ... id
        self.__oArgumentParser.add_argument(
            "--id",
            type=int,
            metavar="<int>",
            help="Item ID (index)",
        )

        # ... page
        self.__oArgumentParser.add_argument(
            "--page",
            type=int,
            metavar="<int>",
            default=1,
            help="List page (starting from 1; default: 1)",
        )

        # ... percent
        self.__oArgumentParser.add_argument(
            "--percent",
            type=int,
            metavar="<int>",
            help="Percentage",
        )

        # ... recipients
        self.__oArgumentParser.add_argument(
            "--recipient",
            action="append",
            metavar="<phone number>",
            help="Recipient phone number (may be specified multiple times)",
        )

        # ... state
        self.__oArgumentParser.add_argument(
            "--state",
            type=int,
            metavar="<int>",
            help="State",
        )

        # ... text
        self.__oArgumentParser.add_argument(
            "--text",
            type=str,
            metavar="<str>",
            help="Text (message)",
        )

        # ... timeout
        self.__oArgumentParser.add_argument(
            "--timeout",
            type=int,
            metavar="<int>",
            default=5000,
            help="Timeout, in milliseconds (ping, traceroute, etc.)",
        )

    # ------------------------------------------------------------------------------
    # METHODS
    # ------------------------------------------------------------------------------

    def run(self):
        # Initialize

        # ... arguments
        try:
            self.__oArguments = self.__oArgumentParser.parse_args()
        except Exception as e:
            logger.error(f"Failed to parse arguments; {str(e)}")
            return errno.EINVAL

        # ... verbosity
        if self.__oArguments.debug:
            logger.setLevel(logging.DEBUG)

        # ... configuration
        try:
            self.__dConfig = HuaweiHilink_Config.load(self.__oArguments.config)
        except Exception as e:
            logger.error(f"Failed to load configuration; {str(e)}")
            return errno.EINVAL

        # Category
        sCategory = self.__oArguments.category
        dCategory = HUAWEI_HILINK_API[sCategory]
        dCommands = dCategory["commands"]

        # ... help
        if self.__oArguments.command == "help":
            print(f"{sCategory}")
            for sCommand, dCommand in dCommands.items():
                sHelp = dCommand.get("help")
                print(
                    f"  {sCommand}: {sHelp}" if sHelp is not None else f"  {sCommand}"
                )
                dArguments = dCommand.get("uargs", {})
                for sFunctionArg, sUserArg in dArguments.items():
                    print(f"    --{sUserArg} <{sFunctionArg}>")
            return 0

        # ... command
        sCommand = self.__oArguments.command
        if sCommand not in dCommands:
            logging.error(f"Invalid command ({sCategory}:{sCommand})")
            return errno.EINVAL

        # API

        # ... connection
        sScheme = "https" if self.__dConfig["ssl"] else "http"
        sEndpoint = self.__dConfig["endpoint"]
        try:
            if len(self.__dConfig["password"]):
                oConnection = AuthorizedConnection(
                    f"{sScheme}://{sEndpoint}/",
                    username=self.__dConfig["username"],
                    password=self.__dConfig["password"],
                )
            else:
                oConnection = Connection(f"{sScheme}://{sEndpoint}/")
        except Exception as e:
            logger.error(
                f"Failed to connect to endpoint ({sScheme}://{sEndpoint}/); {str(e)}"
            )
            return errno.EFAULT

        # ... class (category)
        try:
            sClass = dCategory["class"]
            cClass = getattr(
                __import__(
                    f"huawei_lte_api.api.{sClass}", fromlist=["huawei_lte_api.api"]
                ),
                sClass,
            )
        except Exception as e:
            logger.error(f"Failed to load API class ({sCategory}); {str(e)}")
            return errno.EFAULT
        oCategory = cClass(oConnection)

        # ... method (command)
        dCommand = dCommands[sCommand]
        try:
            sMethod = dCommand["method"]
            fMethod = getattr(oCategory, sMethod)
            dArguments = {}
            for sFunctionArg, sSystemArg in dCommand.get("sargs", {}).items():
                dArguments[sFunctionArg] = sSystemArg
            for sFunctionArg, sUserArg in dCommand.get("uargs", {}).items():
                if hasattr(self.__oArguments, sUserArg):
                    dArguments[sFunctionArg] = getattr(self.__oArguments, sUserArg)
                elif sUserArg in self.__dConfig:
                    dArguments[sFunctionArg] = self.__dConfig[sUserArg]
                else:
                    logger.error(
                        f"Invalid command argument ({sCategory}:{sCommand}:{sFunctionArg})"
                    )
                    return errno.EFAULT
                if dArguments[sFunctionArg] is None:
                    logger.error(
                        f"Missing command argument ({sCategory}:{sCommand}: --{sUserArg})"
                    )
                    return errno.EINVAL
            logger.debug(
                f"Calling API method: huawei_lte_api.api.{sClass}.{sMethod}({dArguments})"
            )
            dOutput = fMethod(**dArguments)
        except Exception as e:
            logger.error(
                f"Failed to execute API method ({sCategory}:{sCommand}); {str(e)}"
            )
            return errno.EFAULT

        # ... output
        if self.__oArguments.field is not None:
            sField = self.__oArguments.field
            if sField in dOutput:
                print(dOutput[self.__oArguments.field])
            else:
                logger.warning(
                    f"Command output has no such field ({sCategory}:{sCommand} -> {sField})"
                )
        else:
            print(json.dumps(dOutput, sort_keys=True, indent=2))

        # ... logout
        if isinstance(oConnection, AuthorizedConnection) and oConnection.logged_in:
            oConnection.user.logout()


# ------------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        logging.basicConfig()
        sys.exit(HuaweiHilink().run())
    except KeyboardInterrupt:
        sys.exit(-2)
