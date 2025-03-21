#!/usr/bin/env python3
"""Envertech EVT "local mode" TCP/14889 client.

This utility queries the embedded TCP/14889 server of Envertech EVT microinverters -
using the so-called "Local Mode" - and decodes the received AC/DC/solar production data.

Usage:

    # Query a given EVT microinverter, specified by its IPv4 address and ID
    # (last 8 digits of its S/N), and output the result in JSON format
    envertec-tcp14889.py --json 10.10.100.254 12345678

    # Discover EVT microinverters in a given network, specified by the localhost
    # IPv4 address and network prefix length (in bits)
    envertec-tcp14889.py --discover 10.10.100.150/24

    # Other options
    envertec-tcp14889.py --help

It has been tested on the following models:
- EVT400-R (firmware 111.111)
"""
import logging
import socket
from contextlib import suppress
from functools import reduce
from struct import unpack
from time import time
from typing import Tuple

LOGGER = logging.getLogger("EnvertecTcp14889")


class EnvertecTcp14889:
    """Query and decode Envertech EVT microinverters TCP/14889 server data."""

    ############################################################################
    # Constants
    #

    LOGGER = LOGGER

    CONFIG = {
        "id": None,
        "host": "10.10.100.254",
        "port": 14889,
        "timeout": 10.0,
        "tries": 3,
    }

    # Protocol
    # "message": {
    #   "part(fixed)": (start, end, bytes, None)
    #   "part(computed)": (start, end, decode/encode function, unit)
    # }
    PROTOCOL_MESSAGES = {
        # Inverter data query (@ TCP/14889); generally:
        # - REF: https://www.photovoltaikforum.com/thread/240683-envertech-evt800-wlan-ohne-cloude-lokal-auslesen/ (with thanks)
        # - data[2] = length of message
        # - data[-2] = checksum of message (data[:-2])
        # Heartbeat, sent every couple of seconds while connected to the EVT
        "heartbeat": {
            #                                     1  1  1  1  1  1
            #       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
            #    -------------------------------------------------
            # 00 ¦ 68 00 20 68 10 06 ID ID ID ID 00 00 00 00 00 00
            # 16 ¦ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 CS 16
            "_header": (0, 5, b"\x68\x00\x20\x68\x10\x06", None),
            "id": (6, 9, lambda v: v.hex(), None),
            "_suffix": (10, 29, b"\x00" * 20, None),
            "_cksum": (30, 30, lambda v: v[0], None),
            "_eof": (31, 31, b"\x16", None),
        },
        # Request for inverter data
        "data_req": {
            #                                     1  1  1  1  1  1
            #       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
            #    -------------------------------------------------
            # 00 ¦ 68 00 20 68 10 77 ID ID ID ID 00 00 00 00 00 00
            # 16 ¦ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 CS 16
            "_header": (0, 5, b"\x68\x00\x20\x68\x10\x77", None),
            "id": (6, 9, lambda v: bytes.fromhex(v), None),
            "_suffix": (10, 29, b"\x00" * 20, None),
            "_cksum": (30, 30, lambda v: bytes([v]), None),
            "_eof": (31, 31, b"\x16", None),
        },
        # Inverter data response
        "data_resp": {
            #                                     1  1  1  1  1  1
            #       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
            #    -------------------------------------------------
            # 00 ¦ 68 00 56 68 10 51 ID ID ID ID 6f 00 6f 00 00 00
            # 16 ¦ 00 00 00 00 ID ID ID ID 6f 6f 2f 01 00 b5 00 00
            # 32 ¦ c5 d0 1b c0 3b fc 32 19 02 00 00 00 00 00 00 00
            # 48 ¦ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            # 64 ¦ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            # 80 ¦ 00 00 00 00 CS 16
            "_header": (0, 5, b"\x68\x00\x56\x68\x10\x51", None),
            "id": (6, 9, lambda v: v.hex(), None),
            "units": [
                {
                    "id": (20, 23, lambda v: v.hex(), None),
                    "firmware": (24, 25, lambda v: "{}.{}".format(*unpack("2b", v)), None),
                    "inputDcVoltage": (26, 27, lambda v: unpack(">H", v)[0] / 512, "V"),
                    "outputAcPower": (28, 29, lambda v: unpack(">H", v)[0] / 64, "W"),
                    "outputTotal": (30, 33, lambda v: unpack(">L", v)[0] / 8192, "kWh"),
                    "temperature": (34, 35, lambda v: unpack(">H", v)[0] / 128 - 40, "C"),
                    "outputAcVoltage": (36, 37, lambda v: unpack(">H", v)[0] / 64, "V"),
                    "outputAcFrequence": (38, 39, lambda v: unpack(">H", v)[0] / 256, "Hz"),
                },
                {
                    "id": (52, 55, lambda v: v.hex(), None),
                    "firmware": (56, 57, lambda v: "{}.{}".format(*unpack("2b", v)), None),
                    "inputDcVoltage": (58, 59, lambda v: unpack(">H", v)[0] / 512, "V"),
                    "outputAcPower": (60, 61, lambda v: unpack(">H", v)[0] / 64, "W"),
                    "outputTotal": (62, 65, lambda v: unpack(">L", v)[0] / 8192, "kWh"),
                    "temperature": (66, 67, lambda v: unpack(">H", v)[0] / 128 - 40, "C"),
                    "outputAcVoltage": (68, 69, lambda v: unpack(">H", v)[0] / 64, "V"),
                    "outputAcFrequence": (70, 71, lambda v: unpack(">H", v)[0] / 256, "Hz"),
                },
            ],
            "_cksum": (84, 84, lambda v: v[0], None),
            "_eof": (85, 85, b"\x16", None),
        },
        # Inverters discovery
        # Ping (NB: not sure which is really needed)
        # (@ UDP/48889)
        "discover_ping_1": {
            # ASCII: "LOCALCON-1508-READ"
            "#raw": (0, None, "LOCALCON-1508-READ".encode(), None),
        },
        # (@ UDP/48899)
        "discover_ping_2": {
            # ASCII: "www.usr.cn"
            "#raw": (0, None, "www.usr.cn".encode(), None),
        },
        # Pong
        "discover_pong": {
            # ASCII: "<IPv4>,<MAC>,<ID>"
            "#raw": (0, None, lambda v: v.decode(), None),
        },
    }

    # {"header": "message"}
    PROTOCOL_HEADERS = {v["_header"][2]: k for k, v in PROTOCOL_MESSAGES.items() if "_header" in v}

    ############################################################################
    # Construction
    #

    def __init__(self, config: dict = None):
        """Initialization.

        Args:
             config: Configuration parameters; see self.config()
        """
        self.config(config or {})

    def config(self, config: dict):
        """Configuration.

        Args:
            config: Configuration parameters:
                id: Inverter ID (last 8 digits of its S/N); default: None (auto-detected)
                host: Inverter TCP server IP(v4) address or (DNS) hostname; default: 10.10.100.154
                port: Inverter TCP server port; default: 14889
                timeout: Query timeout (seconds); default: 10.0
                tries: Query attempts; default: 3
        """
        self._config = self.CONFIG | config

    ############################################################################
    # Decode/Encode
    #

    @classmethod
    def checksum(cls, data: bytes) -> int:
        """Returns the checksum corresponding to the given data."""
        return reduce(lambda x, y: (x + y) & 0xFF, data + b"\x55")

    @classmethod
    def _decodeParts(cls, message: str, data: bytes, parts: dict, withUnit: bool = False) -> dict:
        """Decodes the given data parts.

        Args:
            message: Message type
            data: Full message data
            parts: {"part": (start, end, decoder, unit)} decoding specification
            withUnit: Include unit along data values

        Returns: decoded parts:
          - with units: {"part": (value, "unit")}
          - without units: {"part": value}
        """
        decoded = {}
        for part, decoder in parts.items():
            if isinstance(decoder, list):
                decoded[part] = []
                for decoder_ in decoder:
                    decoded_ = cls._decodeParts(message, data, decoder_, withUnit)
                    if "id" not in decoded_ or cls.decodedValue(decoded_["id"]) != "00000000":
                        decoded[part].append(decoded_)
            elif isinstance(decoder, dict):
                decoded_ = cls._decodeParts(message, data, decoder, withUnit)
                if "id" not in decoded_ or cls.decodedValue(decoded_["id"]) != "00000000":
                    decoded[part] = decoded_
            else:
                try:
                    start, end, decode, unit = decoder
                    if end is None:
                        end = len(data) - 1
                    dataPart = data[start : end + 1]
                    if isinstance(decode, bytes):
                        if dataPart != decode:
                            raise ValueError(f"Invalid data ({message}[{start}:{end+1}]): {dataPart})")
                    else:
                        decoded_ = decode(dataPart)
                        decoded[part] = (decoded_, unit) if withUnit else decoded_
                except IndexError:
                    raise ValueError(f"Invalid data ({message}); length < {end+1}")
                except Exception as e:
                    raise ValueError(f"Invalid data ({message}:{part}); {e}")

        if "_cksum" in decoded and cls.decodedValue(decoded["_cksum"]) != cls.checksum(data[:-2]):
            raise ValueError(f"Invalid data ({message}); invalid checksum")

        return {k: v for k, v in decoded.items() if not k[0] == "_"}

    @classmethod
    def decode(cls, data: bytes, withUnit: bool = False) -> Tuple[str, dict]:
        """Decodes the given data.

        Args:
            data: Full message data
            withUnit: Include unit along data values

        Returns: decoded data
          - with units: ("message", {"part": (value, "unit")})
          - without units: ("message", {"part": value})
        """
        dataN = len(data)
        if dataN < 6:
            raise ValueError("Invalid data: length < 6")
        if dataN != data[2]:
            raise ValueError(f"Invalid data: length != {data[2]}")

        for header, message in cls.PROTOCOL_HEADERS.items():
            if data.startswith(header):
                break
            message = None
        if message is None:
            raise ValueError(f"Invalid/unknown header: {data[0:6].hex()}")

        return message, cls._decodeParts(message, data, cls.PROTOCOL_MESSAGES[message], withUnit)

    @classmethod
    def decodedValue(cls, value):
        """Returns the data value, stripped from its unit."""
        return value[0] if isinstance(value, tuple) else value

    @classmethod
    def encode(cls, message: str, data: dict = None) -> bytes:
        """Encodes the given data.

        Args:
            message: The message to be encoded
            data: Message parts values
        """
        data = data or {}
        parts = cls.PROTOCOL_MESSAGES[message]
        if "#raw" in parts:
            encoded = parts["#raw"][2]
        else:
            length = parts["_header"][2][2]  # NB: header[2] is message length
            encoded = bytearray(length)
            for part, (start, end, encode, _) in parts.items():
                if part == "_cksum":
                    continue  # to do after all other parts are encoded (see below)
                if not isinstance(encode, bytes):
                    encode = encode(data[part])
                encoded[start : end + 1] = encode

        # Checksum
        if "_cksum" in parts:
            start, end, encode, _ = parts["_cksum"]
            encoded[start : end + 1] = encode(cls.checksum(encoded[:-2]))

        return bytes(encoded)

    ############################################################################
    # TCP Client
    #

    @staticmethod
    def _timeout(deadline: float, sock: socket.socket = None):
        wait = deadline - time()
        if wait <= 0:
            raise TimeoutError()
        if sock:
            # We might as well add 100ms to account for the time to carry out
            # the next network operation
            sock.settimeout(wait + 0.1)

    def query(self, withUnit: bool = False) -> dict:
        """Query and decode Envertech EVT microinverters TCP/14889 server data.

        Args:
            withUnit: Include unit along data values

        Returns: decoded data
          - with units: {"part": (value, "unit")}
          - without units: {"part": value}
        """
        id = self._config["id"]
        host = self._config["host"]
        port = self._config["port"]
        deadline = time() + self._config["timeout"]
        tries = self._config["tries"]
        socketTcp = None
        while True:
            try:
                if socketTcp is None:
                    socketTcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self._timeout(deadline, socketTcp)
                    self.LOGGER.debug(f"Opening TCP socket: {host}:{port}")
                    socketTcp.connect((host, port))

                # If ID is provided, we can send a "data_req" message
                if id is not None:
                    # Send
                    data = self.encode("data_req", {"id": id})
                    self.LOGGER.debug(f"Sending 'data_req' message: {data.hex()} ({len(data)})")
                    socketTcp.send(data)

                # Receive
                # (header)
                self._timeout(deadline, socketTcp)
                data = socketTcp.recv(6)
                self.LOGGER.debug(f"Received message header: {data.hex()} (6)")
                # (payload)
                self._timeout(deadline, socketTcp)
                data += socketTcp.recv(data[2] - 6)  # NB: data[2] is message length
                self.LOGGER.debug(f"Received message: {data.hex()} ({len(data)})")

                message, parts = self.decode(data, withUnit)

                id_ = self.decodedValue(parts["id"])
                if id and id != id_:
                    raise ValueError(f"Invalid ID: {id_} != {id}")

                if message == "data_resp":
                    break

                if id is None:
                    self.LOGGER.debug(f"Using ID from '{message}' message: {id_}")
                    id = id_
                else:
                    self.LOGGER.debug(f"Ignoring '{message}' message")
            except Exception as e:
                self.LOGGER.error(f"Failed to query inverter: {host}:{port}; {e.__class__.__name__}: {e}")
                with suppress(Exception):
                    socketTcp.close()
                socketTcp = None
                tries -= 1
                if not tries:
                    raise

        with suppress(Exception):
            socketTcp.close()

        self.LOGGER.debug(f"Inverter data successfully queried: {parts}")
        return parts

    ############################################################################
    # UDP Discovery
    #

    @classmethod
    def discover(cls, bind: str, timeout: float = 10.0, tries: int = 3) -> list:
        """Discover Envertech EVT microinverters using UDP/48899 discovery.

        Args:
            bind: Bind IP(v4) address and network length (in bits)
            timeout: Discovery timeout (seconds); default: 10.0
            tries: Discovery attempts; default: 3

        Returns: discovered inverters: {"ID": ("IP", "MAC")}
        """
        from ipaddress import IPv4Network

        discovered = {}
        network = IPv4Network(bind, strict=False)
        broadcast = str(network.broadcast_address)
        netmask = network.prefixlen
        bind = f"{bind}/".split("/", 1)[0]
        deadline = time() + timeout
        tries = tries
        ping = cls.encode("discover_ping_2")
        ping_next = 0
        socketUdp = None
        while True:
            try:
                if socketUdp is None:
                    socketUdp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    socketUdp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    socketUdp.bind((bind, 48899))
                    socketUdp.settimeout(0.1)

                # Ping
                now = time()
                if now > ping_next:
                    cls.LOGGER.debug(
                        f"Sending 'discover_ping_2' message: {ping.decode()} ({len(ping)}) -> {broadcast}:48899"
                    )
                    socketUdp.sendto(ping, (broadcast, 48899))
                    ping_next = now + max((timeout / 3, 2.0))

                # Pong
                cls._timeout(deadline)
                try:
                    pong, source = socketUdp.recvfrom(37)  # max. length of "discover_pong" message
                    cls.LOGGER.debug(
                        f"Received 'discover_pong' message: {pong.decode()} ({len(pong)}) <- {source[0]}:{source[1]}"
                    )
                    data = cls._decodeParts("discover_pong", pong, cls.PROTOCOL_MESSAGES["discover_pong"])["#raw"]

                    ip, mac, id = data.split(",", 2)
                    if len(id) != 8:
                        raise ValueError(f"Invalid/incomplete message: {data}")
                    discovered[id] = (ip, mac)
                except TimeoutError:
                    pass
                except ValueError as e:
                    cls.LOGGER.error(f"Invalid discovery response; {e}")
            except Exception as e:
                tries -= 1
                if isinstance(e, TimeoutError) or not tries:
                    break
                cls.LOGGER.error(f"Failed to discover inverters on: {broadcast}/{netmask}; {e.__class__.__name__}: {e}")
                with suppress(Exception):
                    socketUdp.close()
                socketUdp = None

        with suppress(Exception):
            socketUdp.close()

        cls.LOGGER.debug(f"Inverters successfully discovered: {', '.join(discovered)}")
        return discovered


################################################################################
# Main
#

if __name__ == "__main__":
    import sys
    from argparse import ArgumentParser
    from datetime import datetime as DateTime
    from json import dumps as _jsonDumps

    parser = ArgumentParser("Query and decode Envertech EVT microinverters TCP/14889 server data")
    parser.add_argument(
        "host",
        type=str,
        nargs="?",
        default="10.10.100.254",
        help="Inverter TCP server IP(v4) address or (DNS) hostname",
    )
    parser.add_argument("id", type=str, nargs="?", default=None, help="Inverter ID (last 8 digits of its S/N)")
    parser.add_argument("-U", "--unit", type=int, default=None, help="Output only the specified unit data")
    parser.add_argument("-J", "--json", action="store_true", help="Format output as JSON")
    parser.add_argument("-p", "--port", type=int, default=14889, help="Inverter TCP server port")
    parser.add_argument("-t", "--timeout", type=float, default=10.0, help="Query timeout (seconds)")
    parser.add_argument("-i", "--tries", type=int, default=3, help="Query attempts")
    parser.add_argument(
        "--discover", type=str, default=None, help="Perform inverters UDP discovery, within specified IPv4/prefix"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug messages")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    try:
        if args.discover:
            config = {
                "bind": args.discover,
                "timeout": args.timeout,
                "tries": args.tries,
            }
            data = EnvertecTcp14889.discover(**config)
            data = {"inverters": data}
        else:
            config = {
                "id": args.id,
                "host": args.host,
                "port": args.port,
                "timeout": args.timeout,
                "tries": args.tries,
            }
            evt = EnvertecTcp14889(config)
            data = evt.query(withUnit=not args.json)

        if args.unit is not None and "units" in data:
            data = data["units"][args.unit]

        if args.json:
            data["time"] = DateTime.now().isoformat()
            sys.stdout.write(_jsonDumps(data))
        else:

            def __kv(key, value):
                if isinstance(value, list):
                    for i, j in enumerate(value):
                        sys.stdout.write(f"{key.upper()}[{i}]:\n")
                        for k, v in j.items():
                            __kv(k, v)
                elif isinstance(value, dict):
                    sys.stdout.write(f"{key.upper()}:\n")
                    for k, v in value.items():
                        __kv(k, v)
                else:
                    value, unit = value
                    sys.stdout.write(f"{key}: {value} {unit or ''}\n")

            for k, v in data.items():
                __kv(k, v)

    except Exception as e:
        if args.debug:
            raise
        sys.stderr.write(f"ERROR: {e}\n")
        sys.exit(1)
