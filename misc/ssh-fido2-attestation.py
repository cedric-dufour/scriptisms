#!/usr/bin/env python3
# REF: https://github.com/cedric-dufour/scriptisms/blob/master/misc/ssh-fido2-attestation.py

# ------------------------------------------------------------------------------
# DEPENDENCIES
# ------------------------------------------------------------------------------

# Standard
import argparse
from base64 import b64decode
import errno
from hashlib import sha256
from inspect import getdoc
from io import BytesIO
import logging
import os
import sys
from uuid import UUID

# Non-standard
# (python3-cryptography)
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

# (python3-fido2)
from fido2 import cbor, cose
from fido2.ctap2 import AuthenticatorData
from fido2.attestation import (
    InvalidSignature,
    PackedAttestation,
    verify_x509_chain,
)


## Logging
logger = logging.getLogger("ssh-fido2-attestation")


# ------------------------------------------------------------------------------
# CONSTANTS
# ------------------------------------------------------------------------------

SSH_FIDO2_ATTESTATION_VERSION = "0.0.20220905"


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
                f"SSH_FIDO2_Attestation_PublicKey:loadFromFile: Loading/parsing attestation from file ({path})"
            )
            with open(path, "rb") as public_key_file:
                # Base64 data
                public_key_base64 = public_key_file.read().decode().split(" ")[1]
                public_key_reader = BytesIO(b64decode(public_key_base64))

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

        # REF: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
        try:
            logger.debug(
                f"SSH_FIDO2_Attestation:loadFromFile: Loading/parsing attestation from file ({path})"
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
                "SSH_FIDO2_Attestation:_decodeFromRaw: Decoding raw attestation data"
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

    def verifyAttestation(
        self,
        challenge: bytes,
        authorities: list,
    ):
        """
        Verify the SSH FIDO2 attestation
        """

        # Signature
        logger.debug(
            "SSH_FIDO2_Attestation:verifyAttestation: Verifying attestation signature"
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

        # Authority
        if authorities is not None:
            logger.debug(
                "SSH_FIDO2_Attestation:verifyAttestation: Verifying attestation authority"
            )
            if len(authorities) == 0:
                raise SSH_FIDO2_Attestation_Exception(
                    "SSH_FIDO2_Attestation:verifyAttestation: Empty authorities list"
                )
            authority_verified = False
            for authority in authorities:
                try:
                    verify_x509_chain(attestation_result.trust_path + [authority])
                    authority_verified = True
                    break
                except InvalidSignature:
                    continue
            if not authority_verified:
                raise SSH_FIDO2_Attestation_Exception(
                    "SSH_FIDO2_Attestation:verifyAttestation: No authority matches the attestation's"
                )

        # Done
        self.attestation_result = attestation_result

    def verifyAuthenticatorData(
        self,
        application: str,
        user_present: bool,
        user_verified: bool,
    ):
        """
        Verify the SSH FIDO2 authenticator data
        """

        # Application (aka. Relaying Party [RP])
        logger.debug(
            "SSH_FIDO2_Attestation:verifyAuthenticatorData: Verifying application"
        )
        want_rp_id_hash = sha256(application.encode()).digest()
        if want_rp_id_hash != self.authenticator_data.rp_id_hash:
            raise SSH_FIDO2_Attestation_Exception(
                f"SSH_FIDO2_Attestation:verifyAuthenticatorData: Application mismatch (expected: {application})"
            )

        # Flags
        logger.debug("SSH_FIDO2_Attestation:verifyAuthenticatorData: Verifying flags")

        # (attested)
        if not self.authenticator_data.is_attested():
            raise SSH_FIDO2_Attestation_Exception(
                "SSH_FIDO2_Attestation:verifyAuthenticatorData: Authenticator does not attest credential data"
            )

        # (user present, aka. touch)
        if user_present and not self.authenticator_data.is_user_present():
            raise SSH_FIDO2_Attestation_Exception(
                "SSH_FIDO2_Attestation:verifyAuthenticatorData: Authenticator does not require user presence (touch)"
            )

        # (user verified, aka. PIN)
        if user_verified and not self.authenticator_data.is_user_verified():
            raise SSH_FIDO2_Attestation_Exception(
                "SSH_FIDO2_Attestation:verifyAuthenticatorData: Authenticator does not require user verification (PIN)"
            )

    def verifyCredentialData(
        self,
        public_key: SSH_FIDO2_Attestation_PublicKey,
    ):
        """
        Verify the SSH FIDO2 attested credential data (public key)
        """

        # Public key
        logger.debug(
            "SSH_FIDO2_Attestation:verifyCredentialData: Verifying credential data (public key)"
        )
        algorithm = self.authenticator_data.credential_data.public_key[3]
        if algorithm == cose.EdDSA.ALGORITHM:

            if (
                public_key.type not in ("sk-ssh-ed25519@openssh.com")
                or self.authenticator_data.credential_data.public_key[-2]
                != public_key.components["key"]
            ):
                raise SSH_FIDO2_Attestation_Exception(
                    "SSH_FIDO2_Attestation:verifyCredentialData: Public key mismatch (EdDSA)"
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
                    "SSH_FIDO2_Attestation:verifyCredentialData: Public key mismatch (ES256)"
                )

        else:
            raise SSH_FIDO2_Attestation_Exception(
                f"SSH_FIDO2_Attestation:verifyCredentialData: Unsupported public key algorithm ({algorithm})"
            )

    def summary(self, application: str):
        """
        Print a summary of the SSH FIDO2 attestation data
        """

        # REF: https://support.yubico.com/hc/en-us/articles/360016648959-YubiKey-Hardware-FIDO2-AAGUIDs
        aaguid = UUID(bytes=self.authenticator_data.credential_data.aaguid)
        authenticator = x509.load_der_x509_certificate(
            self.RAW.attestation_certificate
        ).subject.rfc4514_string()
        vendor = x509.load_der_x509_certificate(
            self.RAW.attestation_certificate
        ).issuer.rfc4514_string()
        print(f"Authenticator: {authenticator} (AAGUID: {aaguid})")
        print(f"Vendor: {vendor}")
        print(f"Application: {application}")
        print(f"User presence (touch): {self.authenticator_data.is_user_present()}")
        print(f"User verification (PIN): {self.authenticator_data.is_user_verified()}")


class SSH_FIDO2_Attestation_CLI(SSH_FIDO2_Attestation):
    """
    SSH FIDO2 attestation (verifier) command-line client

    Example usage:

    # Random challenge (ideally issued by server)
    dd \\
      bs=1 count=32 \\
      if=/dev/random \\
      of=id_ed25519_sk.challenge

    # Create SSH key
    ssh-keygen \\
      -t ed25519-sk \\
      -O resident \\
      -O verify-required \\
      -O application=ssh:bastion \\
      -O challenge=id_ed25519_sk.challenge \\
      -O write-attestation=id_ed25519_sk.attestation \\
      -N '' \\
      -f id_ed25519_sk

    # Verify SSH key/attestation
    ssh-fido2-attestation \\
      id_ed25519_sk.pub \\
      id_ed25519_sk.challenge \\
      id_ed25519_sk.attestation \\
      -a ssh:bastion \\
      -A YubicoCAs.pem \\
      --summary
    # [[output]]
    #Authenticator: CN=Yubico U2F EE Serial 1449538429,OU=Authenticator Attestation,O=Yubico AB,C=SE (AAGUID: ee882879-721c-4913-9775-3dfcce97072a)
    #Vendor: CN=Yubico U2F Root CA Serial 457200631
    #Application: ssh:bastion
    #User presence (touch): True
    #User verification (PIN): True
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
        self.__argumentParser = argparse.ArgumentParser(
            prog=sys.argv[0].split(os.sep)[-1],
            epilog=getdoc(self),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

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

        # (authorities)
        self.__argumentParser.add_argument(
            "-A",
            "--authorities",
            type=str,
            default=None,
            help="Authorities (PEM) bundle file (default: none)",
        )

        # (no user presence)
        self.__argumentParser.add_argument(
            "--no-user-present",
            action="store_true",
            default=False,
            help="Do not require user presence (UP), aka. touch",
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
            version=(
                f"ssh-fido2-attestation - {SSH_FIDO2_ATTESTATION_VERSION} - http://cedric.dufour.name\n"
            ),
        )

    # ------------------------------------------------------------------------------
    # METHODS
    # ------------------------------------------------------------------------------

    #
    # Helpers
    #

    def __loadChallengeFromFile(self, path: str):
        try:
            with open(path, "rb") as challenge_file:
                return challenge_file.read(32)
        except Exception as e:
            raise SSH_FIDO2_Attestation_Exception(
                f"SSH_FIDO2_Attestation:__loadChallengeFromFile: Failed to load challenge data ({path}); {str(e)}"
            )

    def __loadAuthoritiesFromFile(self, path: str):
        authorities = []
        try:
            with open(self.__arguments.authorities, "r") as authorities_file:
                pem = None
                for line in authorities_file:
                    if "-----BEGIN CERTIFICATE-----" in line:
                        pem = line
                    elif "-----END CERTIFICATE-----" in line:
                        if pem is None:
                            raise RuntimeError("Invalid PEM data")
                        pem += line
                        cert = x509.load_pem_x509_certificate(pem.encode())
                        authorities.append(cert.public_bytes(Encoding.DER))
                        pem = None
                    else:
                        if pem is not None:
                            pem += line
        except Exception as e:
            raise SSH_FIDO2_Attestation_Exception(
                f"SSH_FIDO2_Attestation:__loadAuthoritiesFromFile: Failed to load authorities certificates ({path}); {str(e)}"
            )

        return authorities

    #
    # Entrypoint
    #

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
        challenge = self.__loadChallengeFromFile(self.__arguments.challenge)

        # Load attestation data
        self.loadFromFile(self.__arguments.attestation)

        # Load authorities
        authorities = None
        if self.__arguments.authorities is not None:
            authorities = self.__loadAuthoritiesFromFile(self.__arguments.authorities)

        # Verify attestation data
        self.verifyAttestation(challenge, authorities)
        self.verifyAuthenticatorData(
            self.__arguments.application,
            not self.__arguments.no_user_present,
            not self.__arguments.no_user_verified,
        )
        self.verifyCredentialData(public_key)

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
        logger.error(f"{str(e)}")
        sys.exit(errno.EINVAL)
    except KeyboardInterrupt:
        sys.exit(-2)
