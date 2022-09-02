#!/usr/bin/env python3
# REF: https://github.com/cedric-dufour/scriptisms/blob/master/misc/ssh-fido2-attestation.py

# ------------------------------------------------------------------------------
# DEPENDENCIES
# ------------------------------------------------------------------------------

# Standard
import argparse
import base64
import errno
import hashlib
import io
import logging
import os
import sys

# Non-standard
# (python3-cryptography)
from cryptography import x509
# (python3-fido2)
from fido2 import cbor, cose
from fido2.ctap2 import AuthenticatorData
from fido2.attestation import PackedAttestation


## Logging
logger = logging.getLogger("ssh-fido2-attestation")


# ------------------------------------------------------------------------------
# CONSTANTS
# ------------------------------------------------------------------------------

SSH_FIDO2_ATTESTATION_VERSION = "0.0.20220902"


# ------------------------------------------------------------------------------
# CLASSES
# ------------------------------------------------------------------------------


class SSH_FIDO2_Attestation_Exception(Exception):
    """
    Specific exception
    """

    def __init__(self, message):
        Exception.__init__(self)
        self.message = message

    def __str__(self):
        return self.message


class SSH_FIDO2_Attestation_PublicKey:
    """
    SSH public key object
    """

    # ------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    # ------------------------------------------------------------------------------

    def __init__(self):
        """
        Constructor.
        """

        # Fields
        self.type = None
        self.base64 = None
        self.components = None

    # ------------------------------------------------------------------------------
    # METHODS
    # ------------------------------------------------------------------------------

    def loadFromFile(self, path: str):
        """
        Load/parse the SSH public key from the given file path
        """

        try:
            logger.debug(
                f"SSH_FIDO2_Attestation_PublicKey:loadFromFile: Loading/parsing attestation from file ({path}) ..."
            )
            with open(path, "rb") as public_key_file:
                # Base64 data
                public_key_base64 = public_key_file.read().decode().split(" ")[1]
                public_key_reader = io.BytesIO(base64.b64decode(public_key_base64))

                # Key type
                data_length = int.from_bytes(public_key_reader.read(4), "big")
                logger.debug(
                    f"SSH_FIDO2_Attestation_PublicKey:loadFromFile: Reading {data_length} bytes as key type"
                )
                type = public_key_reader.read(data_length)
                logger.debug(
                    f"SSH_FIDO2_Attestation_PublicKey:loadFromFile: Parsed key type: {type}"
                )

                # Parse (according to key type)
                components = {}
                if type == b"sk-ssh-ed25519@openssh.com":

                    # Public key
                    data_length = int.from_bytes(public_key_reader.read(4), "big")
                    logger.debug(
                        f"SSH_FIDO2_Attestation_PublicKey:loadFromFile: Reading {data_length} bytes as public key"
                    )
                    if data_length != 32:
                        raise SSH_FIDO2_Attestation_Exception(
                            f"SSH_FIDO2_Attestation_PublicKey:loadFromFile: Invalid public key length ({data_length})"
                        )
                    components["key"] = public_key_reader.read(32)

                elif type == b"sk-ecdsa-sha2-nistp256@openssh.com":

                    # Curve
                    data_length = int.from_bytes(public_key_reader.read(4), "big")
                    logger.debug(
                        f"SSH_FIDO2_Attestation_PublicKey:loadFromFile: Reading {data_length} bytes as curve"
                    )
                    components["curve"] = public_key_reader.read(data_length)

                    # Public key
                    data_length = int.from_bytes(public_key_reader.read(4), "big")
                    logger.debug(
                        f"SSH_FIDO2_Attestation_PublicKey:loadFromFile: Reading {data_length} bytes as public key (X)"
                    )
                    if data_length != 65:
                        raise SSH_FIDO2_Attestation_Exception(
                            f"SSH_FIDO2_Attestation_PublicKey:loadFromFile: Invalid public key length ({data_length})"
                        )
                    public_key_reader.read(1)
                    # (x)
                    components["key_x"] = public_key_reader.read(32)
                    # (y)
                    components["key_y"] = public_key_reader.read(32)

                else:
                    raise SSH_FIDO2_Attestation_Exception(
                        f"SSH_FIDO2_Attestation_PublicKey:loadFromFile: Invalid/unsupported key type ({type})"
                    )

        except Exception as e:
            raise SSH_FIDO2_Attestation_Exception(
                f"SSH_FIDO2_Attestation_PublicKey:loadFromFile: Failed to load/parse data from attestation file ({path}); {str(e)}"
            )

        # Done
        self.type = type.decode()
        self.base64 = public_key_base64
        self.components = components


class SSH_FIDO2_Attestation:
    """
    SSH FIDO2 attestation object
    """

    # ------------------------------------------------------------------------------
    # SUBCLASSES
    # ------------------------------------------------------------------------------

    class RAW:
        def __init__(self):
            self.magic = None
            self.attestation_certificate = None
            self.attestation_signature = None
            self.authenticator_data = None

    # ------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    # ------------------------------------------------------------------------------

    def __init__(self):
        """
        Constructor.
        """

        # Fields
        self.RAW = self.RAW()
        self.magic = None
        self.authenticator_data = None
        self.attestation_result = None

    # ------------------------------------------------------------------------------
    # METHODS
    # ------------------------------------------------------------------------------

    def loadFromFile(self, path: str):
        """
        Load/parse the raw SSH FIDO2 attestation data from the given file path
        """

        try:
            logger.debug(
                f"SSH_FIDO2_Attestation:loadFromFile: Loading/parsing attestation from file ({path}) ..."
            )
            with open(path, "rb") as attestation_file:
                # Magic ID
                data_length = int.from_bytes(attestation_file.read(4), "big")
                logger.debug(
                    f"SSH_FIDO2_Attestation:loadFromFile: Reading {data_length} bytes as magic ID"
                )
                magic = attestation_file.read(data_length)
                logger.debug(
                    f"SSH_FIDO2_Attestation:loadFromFile: Parsed magic ID: {magic}"
                )

                # Parse (according to magic ID)
                if magic == b"ssh-sk-attest-v01":

                    # Attestation certificate
                    data_length = int.from_bytes(attestation_file.read(4), "big")
                    logger.debug(
                        f"SSH_FIDO2_Attestation:loadFromFile: Reading {data_length} bytes as attestation certificate"
                    )
                    attestation_certificate = attestation_file.read(data_length)

                    # Attestation signature
                    data_length = int.from_bytes(attestation_file.read(4), "big")
                    logger.debug(
                        f"SSH_FIDO2_Attestation:loadFromFile: Reading {data_length} bytes as attestation signature"
                    )
                    attestation_signature = attestation_file.read(data_length)

                    # Authenticator data
                    data_length = int.from_bytes(attestation_file.read(4), "big")
                    logger.debug(
                        f"SSH_FIDO2_Attestation:loadFromFile: Reading {data_length} bytes as authenticator data"
                    )
                    authenticator_data = attestation_file.read(data_length)

                else:
                    raise SSH_FIDO2_Attestation_Exception(
                        f"SSH_FIDO2_Attestation:loadFromFile: Invalid/unsupported magic ID ({magic})"
                    )

        except Exception as e:
            raise SSH_FIDO2_Attestation_Exception(
                f"SSH_FIDO2_Attestation:loadFromFile: Failed to load/parse data from attestation file ({path}); {str(e)}"
            )

        # Done
        self.RAW.magic = magic
        self.RAW.attestation_certificate = attestation_certificate
        self.RAW.attestation_signature = attestation_signature
        self.RAW.authenticator_data = authenticator_data
        self._decodeFromRaw()

    def _decodeFromRaw(self):
        """
        Decode the raw SSH FIDO2 attestation data
        """

        try:
            logger.debug(
                "SSH_FIDO2_Attestation:_decodeFromRaw: Decoding raw attestation data ..."
            )

            # Magic ID
            # (assume UTF-8 encoded string)
            magic = self.RAW.magic.decode()

            # Decoded data
            authenticator_data = AuthenticatorData(
                cbor.decode(self.RAW.authenticator_data)
            )
            logger.debug(
                f"SSH_FIDO2_Attestation:_decodeFromRaw: Parsed authenticator data: {authenticator_data}"
            )

        except Exception as e:
            raise SSH_FIDO2_Attestation_Exception(
                f"SSH_FIDO2_Attestation:_decodeFromRaw: Failed to decode raw attestation data; {str(e)}"
            )

        # Done
        self.magic = magic
        self.authenticator_data = authenticator_data

    def verify(
        self,
        application: str,
        challenge: bytes,
        public_key: SSH_FIDO2_Attestation_PublicKey,
        user_present: bool,
        user_verified: bool,
    ):
        """
        Verify the SSH FIDO2 attestation data match expectations
        """

        # Application (aka. Relaying Party [RP])
        logger.debug("SSH_FIDO2_Attestation:verify: Verifying application ...")
        want_rp_id_hash = hashlib.sha256(application.encode()).digest()
        if want_rp_id_hash != self.authenticator_data.rp_id_hash:
            raise SSH_FIDO2_Attestation_Exception(
                f"SSH_FIDO2_Attestation:verify: Application mismatch (expected: {application})"
            )

        # Flags
        logger.debug("SSH_FIDO2_Attestation:verify: Verifying flags ...")

        # (attested)
        if not self.authenticator_data.is_attested():
            raise SSH_FIDO2_Attestation_Exception(
                "SSH_FIDO2_Attestation:verify: Authenticator does not attest credential data"
            )

        # (user present)
        if user_present and not self.authenticator_data.is_user_present():
            raise SSH_FIDO2_Attestation_Exception(
                "SSH_FIDO2_Attestation:verify: Authenticator does not require user presence (touch)"
            )

        # (user verified, aka. PIN)
        if user_verified and not self.authenticator_data.is_user_verified():
            raise SSH_FIDO2_Attestation_Exception(
                "SSH_FIDO2_Attestation:verify: Authenticator does not require user verification (PIN)"
            )

        # Signature
        logger.debug(
            "SSH_FIDO2_Attestation:verify: Verifying attestation signature ..."
        )
        attestation = PackedAttestation()
        statement = {
            "alg": cose.ES256.ALGORITHM,
            "x5c": [self.RAW.attestation_certificate],
            "sig": self.RAW.attestation_signature,
        }
        client_data_hash = challenge
        attestation_result = attestation.verify(
            statement,
            self.authenticator_data,
            client_data_hash,
        )
        self.attestation_result = attestation_result

        # Public key
        logger.debug(
            "SSH_FIDO2_Attestation:verify: Verifying credential data (public key) ..."
        )
        if public_key is not None:
            algorithm = self.authenticator_data.credential_data.public_key[3]
            if algorithm == cose.EdDSA.ALGORITHM:

                if (
                    public_key.type not in ("sk-ssh-ed25519@openssh.com")
                    or self.authenticator_data.credential_data.public_key[-2]
                    != public_key.components["key"]
                ):
                    raise SSH_FIDO2_Attestation_Exception(
                        "SSH_FIDO2_Attestation:verify: Public key mismatch (EdDSA)"
                    )

            elif algorithm == cose.ES256.ALGORITHM:

                if (
                    public_key.type not in ("sk-ecdsa-sha2-nistp256@openssh.com")
                    or self.authenticator_data.credential_data.public_key[-2]
                    != public_key.components["key_x"]
                    or self.authenticator_data.credential_data.public_key[-3]
                    != public_key.components["key_y"]
                ):
                    raise SSH_FIDO2_Attestation_Exception(
                        "SSH_FIDO2_Attestation:verify: Public key mismatch (ES256)"
                    )

            else:
                raise SSH_FIDO2_Attestation_Exception(
                    f"SSH_FIDO2_Attestation:verify: Unsupported public key algorithm ({algorithm})"
                )

    def summary(self, application: str):
        """
        Print a summary of the SSH FIDO2 attestation data
        """

        authenticator = x509.load_der_x509_certificate(
            self.RAW.attestation_certificate
        ).subject.rfc4514_string()
        vendor = x509.load_der_x509_certificate(
            self.RAW.attestation_certificate
        ).issuer.rfc4514_string()
        print(f"Authenticator: {authenticator}")
        print(f"Vendor: {vendor}")
        print(f"Application: {application}")
        print(f"User presence (touch): {self.authenticator_data.is_user_present()}")
        print(f"User verification (PIN): {self.authenticator_data.is_user_verified()}")


class SSH_FIDO2_Attestation_CLI(SSH_FIDO2_Attestation):
    """
    Command-line client
    """

    # ------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    # ------------------------------------------------------------------------------

    def __init__(self):
        """
        Constructor.
        """

        # Fields
        # (configuration)
        self.__argumentParser = None
        self.__arguments = None

        # Initialization
        self.__initArgumentParser()

    def __initArgumentParser(self):
        """
        Creates the arguments parser (and help generator).
        """

        # Create argument parser
        self.__argumentParser = argparse.ArgumentParser(sys.argv[0].split(os.sep)[-1])

        # (public key)
        self.__argumentParser.add_argument(
            "public_key",
            type=str,
            help="Public key file ('ssh-keygen ...' *.pub output)",
        )

        # (challenge)
        self.__argumentParser.add_argument(
            "challenge",
            type=str,
            help="Challenge file (as in 'ssh-keygen -O challenge=...')",
        )

        # (attestation)
        self.__argumentParser.add_argument(
            "attestation",
            type=str,
            help="Attestation file (as in 'ssh-keygen -O write-attestation=...')",
        )

        # (application, aka. Relaying Party)
        self.__argumentParser.add_argument(
            "-a",
            "--application",
            type=str,
            default="ssh:",
            help="Application (default: 'ssh:')",
        )

        # (no user presence)
        self.__argumentParser.add_argument(
            "--no-user-present",
            action="store_true",
            default=False,
            help="Do not require user presence (UP)",
        )

        # (no user verified)
        self.__argumentParser.add_argument(
            "--no-user-verified",
            action="store_true",
            default=False,
            help="Do not require user verification (UV), aka. PIN",
        )

        # (summary)
        self.__argumentParser.add_argument(
            "--summary",
            action="store_true",
            default=False,
            help="Output a summary of the attestation data",
        )

        # (debug)
        self.__argumentParser.add_argument(
            "--debug",
            action="store_true",
            default=False,
            help="Output debugging messages",
        )

        # (version)
        self.__argumentParser.add_argument(
            "-v",
            "--version",
            action="version",
            version=(f"ssh-fido2-attestation - {SSH_FIDO2_ATTESTATION_VERSION} - http://cedric.dufour.name\n"),
        )

    # ------------------------------------------------------------------------------
    # METHODS
    # ------------------------------------------------------------------------------

    def execute(self):
        # Initialize

        # (arguments)
        try:
            self.__arguments = self.__argumentParser.parse_args()
        except Exception as e:
            logger.error(f"Failed to parse arguments; {str(e)}")
            return errno.EINVAL
        self._debug = self.__arguments.debug

        # (verbosity)
        if self._debug:
            logger.setLevel(logging.DEBUG)

        # Load public key
        public_key = SSH_FIDO2_Attestation_PublicKey()
        public_key.loadFromFile(self.__arguments.public_key)

        # Load challenge data
        challenge = None
        try:
            with open(self.__arguments.challenge, "rb") as challenge_file:
                challenge = challenge_file.read(32)
        except Exception as e:
            raise SSH_FIDO2_Attestation_Exception(
                f"SSH_FIDO2_Attestation:execute: Failed to load challenge data ({self.__arguments.challenge}); {str(e)}"
            )

        # Load attestation data
        self.loadFromFile(self.__arguments.attestation)

        # Verify attestation data
        self.verify(
            self.__arguments.application,
            challenge,
            public_key,
            not self.__arguments.no_user_present,
            not self.__arguments.no_user_verified,
        )

        # Summary (?)
        if self.__arguments.summary:
            self.summary(self.__arguments.application)

        # Done (success)
        return 0


# ------------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        logging.basicConfig()
        logger.setLevel(logging.INFO)
        sys.exit(SSH_FIDO2_Attestation_CLI().execute())
    except SSH_FIDO2_Attestation_Exception as e:
        logger.error(f"Failed to execute command; {str(e)}")
        sys.exit(errno.EINVAL)
    except KeyboardInterrupt:
        sys.exit(-2)
