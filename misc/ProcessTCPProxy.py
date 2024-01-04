#!/usr/bin/env python3
"""Process TCP proxy.

The ProcessTCPProxy class and utility allows to proxy a command/process std{in,out} via TCP. Example given:

    # Proxy mplayer commands
    ProcessTCPProxy mplayer -slave -quiet -nocache http://stream.srg-ssr.ch/m/couleur3/mp3_128

    # Send command via the TCP proxy
    telnet 127.0.0.1 6666
    telnet> pause

A few configuration options are available via environment variables:
 - PROCESSTCPPROXY_BIND:      bind IP address (default: 127.0.0.1)
 - PROCESSTCPPROXY_PORT:      listening (TCP) port (default: 6666)
 - PROCESSTCPPROXY_PASSWORD:  connection password (password must be sent before anything is forwarded to the proxied process)
 - PROCESSTCPPROXY_MIRROR:    if "true" or "yes", mirror the process std{in,out,err} to the current std{in,out,err}
 - PROCESSTCPPROXY_DEBUG:     if "true" or "yes", enable debug logging

Thorougher configuration is also possible via a PROCESSTCPPROXY_CONFIG-defined ConfigParser (INI) file:

    [global]
    #debug = true
    #mirror = true

    [server]
    bind = 127.0.0.1
    port = 6666
    #password = SomePassword

    [ssl]
    #certfile = /path/to/cert.pem
    #keyfile = /path/to/key.pem
    #password = (keyfile password)
    #verify_client = true
    #verify_crl = true
    #cafile = /path/to/cas.pem
    #capath = /path/to/cas.d

In order to quickly get going with SSL:

    # Generate a self-signed certificate
    openssl req -x509 -newkey rsa:2048 -noenc -keyout /path/to/key.pem -out /path/to/cert.pem -days 365

    # Send command via the TCP+SSL proxy
    openssl s_client -connect 127.0.0.1:6666
    openssl> pause

Enjoy!
"""

from configparser import ConfigParser
import logging
from os import getenv, set_blocking
from queue import Empty, Queue
from signal import signal, SIGINT, SIGTERM
from socket import SHUT_RDWR, SOL_SOCKET, SO_REUSEADDR
from socketserver import BaseRequestHandler, TCPServer
from subprocess import PIPE, Popen
from ssl import CERT_REQUIRED, PROTOCOL_TLS_SERVER, SSLContext, VERIFY_CRL_CHECK_LEAF
import sys
from threading import enumerate as _threadEnumerate, Thread
from time import sleep

logger = logging.getLogger("ProcessTCPProxy")


class ProcessThread:
    def __init__(self, command: list = None, mirror: bool = False):
        """Initialisation.

        :param command:  command to execute (executable path and arguments)
        :param mirror:   whether to mirror the process std{in,out,err} to the current std{in,out,err}
        """
        self.command = command
        self._stop = True
        self._mirror = mirror

    def start(self, queueIn: Queue, queueOut: Queue):
        """Thread start.

        :param queueIn:   stdin (input) queue
        :param queueOut:  stdout (output) queue
        :returns:         command exit code
        """
        logger.info(f"[ProcessThread] Starting; command: {self.command}")
        process = Popen(self.command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        set_blocking(process.stdout.fileno(), False)
        set_blocking(process.stderr.fileno(), False)

        self._stop = False
        ret = None
        while True:
            # Have we been stopped ?
            if self._stop:
                logger.info("[ProcessThread] Terminating process")
                try:
                    process.terminate()
                except Exception as e:
                    logger.warning(f"[ProcessThread] Failed to terminate process; {e}")
                break

            # Has process stopped by itself ?
            ret = process.poll()
            if ret is not None:
                break

            # Queued input for stdin ?
            try:
                data = queueIn.get(timeout=0.1)
                if self._mirror:
                    sys.stdout.write("< " + data.decode(sys.stdout.encoding or "utf-8", errors="replace"))
                process.stdin.write(data)
                process.stdin.flush()
            except Empty:
                pass

            # Anything on stdout ?
            for data in process.stdout:
                if self._mirror:
                    sys.stdout.write("> " + data.decode(sys.stdout.encoding or "utf-8", errors="replace"))
                queueOut.put(data)

            # Anything on stderr ?
            for data in process.stderr:
                if self._mirror:
                    sys.stderr.write("! " + data.decode(sys.stderr.encoding or "utf-8", errors="replace"))
        self._stop = True

        logger.debug(f"[ProcessThread] Process terminated; return code: {ret}")
        return ret

    def stop(self):
        """Thread stop."""
        self._stop = True


class TCPServerThread(TCPServer):
    class _RequestHandler(BaseRequestHandler):
        def handle(self):
            """Client request handler."""
            logger.debug("[TCPServerThread:request] Handling client connection")
            authenticated = self.server.password is None
            if not authenticated:
                logger.info("[TCPServerThread:request] Authentication required")
            self.request.settimeout(0.1)  # -> non-blocking read()
            line = b""
            disconnect = False
            while True:
                if disconnect or self.server.stopped():
                    logger.debug("[TCPServerThread:request] Closing client connection")
                    try:
                        self.request.shutdown(SHUT_RDWR)
                        self.request.close()
                    except Exception as e:
                        logger.warning(f"[TCPServerThread:request] Failed to close client connection; {e}")
                    break

                try:
                    while True:
                        data = self.request.recv(1)  # NB: socket.settimeout(...)
                        if data == b"":
                            # Disconnected
                            logger.debug("[TCPServerThread:request] Client disconnected")
                            disconnect = True
                            break
                        line += data
                        if data == b"\n":
                            if authenticated:
                                logger.debug(f"[TCPServerThread:request] Request: {line}")
                                self.server.queueIn.put(line)
                            else:
                                if line.decode().strip() == self.server.password:
                                    logger.info("[TCPServerThread:request] Request: Authenticated")
                                    self.request.sendall(b"ProcessTCPProxy:AUTHENTICATED\n")
                                    authenticated = True
                                else:
                                    logger.warning("[TCPServerThread:request] Request: Unauthorized")
                                    self.request.sendall(b"ProcessTCPProxy:UNAUTHORIZED\n")
                            line = b""
                            break
                except TimeoutError:
                    pass
                try:
                    while True:
                        try:
                            data = self.server.queueOut.get(timeout=0.1)
                            logger.debug(f"[TCPServerThread:request] Response: {data}")
                            self.request.sendall(data)
                        except Empty:
                            break
                except BrokenPipeError:
                    break

    def __init__(self, bind: str = "127.0.0.1", port: int = 6666, password: str = None, ssl: dict = None):
        """Initialisation.

        :param bind:      bind IP address
        :param port:      listening (TCP) port
        :param password:  connection password (password must be sent before anything is forwarded to the proxied process)
        :param ssl:       SSL options as passed to SSLContext.load_cert_chain(...) and SSLContext.load_verify_locations(...)
        """
        self.bind = bind
        self.port = port
        self.password = password
        self.ssl = ssl
        super().__init__((self.bind, self.port), self._RequestHandler)
        self.queueIn = None
        self.queueOut = None
        self._stop = True

    def server_bind(self):
        """Override TCPServer.server_bind(...)."""
        # TLS (SSL context)
        if self.ssl:
            logger.info("[TCPServerThread] Enabling SSL")
            sslContext = SSLContext(PROTOCOL_TLS_SERVER)
            sslContext.load_cert_chain(
                **{k: v for k, v in self.ssl.items() if k in ("certfile", "keyfile", "password")}
            )
            if self.ssl.get("verify_client", "False").lower() in ("true", "yes", "t", "y", "1"):
                sslContext.load_verify_locations(**{k: v for k, v in self.ssl.items() if k in ("cafile", "capath")})
                sslContext.verify_mode = CERT_REQUIRED
                if self.ssl.get("verify_crl", "False").lower() in ("true", "yes", "t", "y", "1"):
                    sslContext.verify_flags = VERIFY_CRL_CHECK_LEAF
            self.socket = sslContext.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)
        self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

        # Binding (listening for client connections)
        super().server_bind()

    def get_request(self):
        """Override TCPServer.get_request(...)."""
        (socket, addr) = super().get_request()

        # TLS (handshake)
        if self.ssl:
            socket.do_handshake()

        return (socket, addr)

    def start(self, queueIn: Queue, queueOut: Queue):
        """Thread start.

        :param queueIn:   stdin (input) queue
        :param queueOut:  stdout (output) queue
        """
        logger.info(f"[TCPServerThread] Starting server: {self.bind}:{self.port}")
        self.queueIn = queueIn
        self.queueOut = queueOut
        self._stop = False
        self.serve_forever(0.1)

    def stop(self):
        """Thread stop."""
        logger.info("[TCPServerThread] Stopping")
        self._stop = True
        try:
            self.shutdown()
            self.server_close()
        except Exception as e:
            logger.warning(f"[TCPServerThread] Failed to stop server; {e}")
        self.queueIn = None
        self.queueOut = None

    def stopped(self):
        return self._stop


class ProcessTCPProxy:
    def __init__(
        self,
        command: list,
        bind: str = "127.0.0.1",
        port: int = 6666,
        password: str = None,
        ssl: dict = None,
        mirror: bool = False,
    ):
        """Initialisation.

        :param command:   command to execute (executable path and arguments)
        :param bind:      bind IP address
        :param port:      listening (TCP) port
        :param password:  connection password (password must be sent before anything is forwarded to the proxied process)
        :param ssl:       SSL options as passed to SSLContext.load_cert_chain(...) and SSLContext.load_verify_locations(...)
        :param mirror:    whether to mirror the process std{in,out,err} to the current std{in,out,err}
        """
        # Process / TCP Server
        self.process = ProcessThread(command, mirror)
        self.server = TCPServerThread(bind, port, password, ssl)
        self._stop = True

    def __signal(self, *args, **kwargs):
        """Signal handler."""
        self.stop()

    def start(self):
        """Process TCP proxy start."""
        logger.debug("[ProcessTCPProxy] Starting")

        # stdin/stdout queues
        queueIn = Queue(maxsize=10)
        queueOut = Queue(maxsize=1000)

        for s in (SIGINT, SIGTERM):
            signal(s, self.__signal)

        threadProcess = Thread(name="ProcessThread", target=self.process.start, args=[queueIn, queueOut])
        threadProcess.start()
        threadTCPServer = Thread(name="TCPServerThread", target=self.server.start, args=[queueIn, queueOut])
        threadTCPServer.start()

        self._stop = False
        while True:
            if self._stop:
                logger.debug("[ProcessTCPProxy] Stopping")
                wait = 10
                threads = []
                while True:
                    threads = [t.name for t in _threadEnumerate() if t.name != "MainThread"]
                    for t in threads:
                        logger.debug(f"[ProcessTCPProxy] Thread still running: {t}")
                    if wait == 0 or len(threads) == 0:
                        break
                    logger.debug(f"[ProcessTCPProxy] Waiting {wait} seconds ...")
                    sleep(1)
                    wait -= 1
                if len(threads) > 0:
                    logger.warning("[ProcessTCPProxy] Threads are still running; exiting ungracefully!")
                break

            # Check both process and server threads are still running
            threads = [t.name for t in _threadEnumerate() if t.name != "MainThread"]
            if "ProcessThread" not in threads:
                logger.info("[ProcessTCPProxy] ProcessThread stopped")
            if "TCPServerThread" not in threads:
                logger.warning("[ProcessTCPProxy] TCPServerThread stopped")
            if len(threads) < 2:
                self.stop()
            else:
                sleep(1)

    def stop(self):
        """Process TCP proxy stop."""
        self._stop = True
        try:
            self.server.stop()
        except Exception:
            pass
        try:
            self.process.stop()
        except Exception:
            pass


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s.%(msecs)03d %(levelname)s %(name)s:%(message)s", datefmt="%Y-%m-%d %H:%M:%S", force=True
    )

    # Configuration
    CONFIG = {
        "global": {"debug": "false", "mirror": "false"},
        "server": {"bind": "127.0.0.1", "port": "6666", "password": ""},
        "ssl": {},
    }

    # (INI file)
    config = getenv("PROCESSTCPPROXY_CONFIG")
    if config is not None:
        config_ = ConfigParser()
        config_.read_dict(CONFIG)
        config_.read(config)
        config = config_
    else:
        config = CONFIG.copy()
    debug = config["global"]["debug"]
    mirror = config["global"]["mirror"]
    bind = config["server"]["bind"]
    port = config["server"]["port"]
    password = config["server"]["password"] or None
    ssl = dict(config["ssl"]) or None

    # (environment)
    debug = getenv("PROCESSTCPPROXY_DEBUG", debug).lower() in ["true", "yes", "t", "y", "1"]
    bind = getenv("PROCESSTCPPROXY_BIND", bind)
    port = int(getenv("PROCESSTCPPROXY_PORT", port))
    password = getenv("PROCESSTCPPROXY_PASSWORD", password)
    mirror = getenv("PROCESSTCPPROXY_MIRROR", mirror).lower() in ["true", "yes", "t", "y", "1"]

    # Logging
    if debug:
        logger.setLevel(logging.DEBUG)

    # Main
    try:
        if len(sys.argv) > 1 and sys.argv[1].strip("-") == "help":
            print(__doc__)
            exit(0)
        if len(sys.argv) < 2:
            raise RuntimeError(f"USAGE: {sys.argv[0]} <command> [<args> ...]")
        ProcessTCPProxy(sys.argv[1:], bind, port, password, ssl, mirror).start()
    except KeyboardInterrupt:
        pass
