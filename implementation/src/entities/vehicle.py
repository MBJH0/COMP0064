import base64
import binascii
import datetime
import hashlib
import random
import secrets
import socket
import sys

import cryptography.hazmat.primitives.asymmetric.ec as ec
import pyDHE
from Crypto.Cipher import ChaCha20
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import NameOID, Certificate

from ..helper import debug


class Vehicle:

    def __init__(self, debug_mode: bool):
        self.debug_mode: bool = debug_mode
        self.__authenticated: bool = False
        self.__conn: socket = None
        self.__nonce: int = -1
        self.__shared_key: int = -1
        self.__pseudonym: str = str(binascii.crc32(random.randbytes(8)))
        self.__other_pseudonym: str = ""
        self.__private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
        self.__certificate: str = self.__generate_certificate(self.__private_key)

    def connect(self, address: tuple[str, int]) -> socket:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(address)
        self.__conn = client
        self.__init_auth()

    def listen(self, address: tuple[str, int]) -> socket:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.bind(address)
        client.listen(1)
        conn, addr = client.accept()
        self.__conn = conn
        self.__authenticate()

    def send_message(self, msg: str) -> None:
        if self.is_authenticated():
            cipher = self.__generate_cipher(shared_key=self.__shared_key, nonce=self.__nonce)
            enc_msg: bytes = cipher.encrypt(msg.encode())
            debug_msg = "SHARED KEY: {0}\nENCRYPTED MESSAGE: {1}"
            debug(txt=debug_msg, params=[self.__shared_key, enc_msg], flag=self.debug_mode)
            self.__conn.send(enc_msg)
        else:
            print(f"{self.__pseudonym}: Receiving vehicle has not been authenticated.")

    def recv_message(self) -> None:
        if self.is_authenticated():
            enc_msg = self.__conn.recv(4096)
            cipher = self.__generate_cipher(shared_key=self.__shared_key, nonce=self.__nonce)
            msg = cipher.decrypt(enc_msg).decode()
            print(f"MESSAGE FROM {self.__other_pseudonym} TO {self.__pseudonym}: {msg}")
        else:
            print(f"{self.__pseudonym}: Sending vehicle has not been authenticated.")

    def __init_auth(self) -> None:
        self.__nonce = nonce_a = secrets.randbits(32)
        certificate_str = self.__certificate.replace('\n', '\n\t')
        debug_msg = "MESSAGE 1 A -> B:\n\tPSEUDONYM A: {0}\n\t" + f"CERTIFICATE A:\n\t{certificate_str}" + "NONCE A: {1}\n"
        debug(txt=debug_msg, params=[self.__pseudonym, nonce_a], flag=self.debug_mode)
        self.__conn.send(f"{self.__pseudonym}>{self.__certificate}>{nonce_a}".encode())
        msg = self.__conn.recv(1244)
        data = msg.decode("utf-8").split('>')
        self.__other_pseudonym: str = data[0]
        certificate_b: Certificate = x509.load_pem_x509_certificate(data=data[1].encode())
        nonce_b: int = int(data[2])
        dh_modulus_b: int = int(data[3])
        dhe: pyDHE.DHE = pyDHE.new()
        dh_modulus_a: int = dhe.getPublicKey()
        nonce_s: int = secrets.randbits(32)
        self.__shared_key: int = dhe.update(B=dh_modulus_b)
        cipher = self.__generate_cipher(shared_key=self.__shared_key, nonce=self.__nonce)
        enc_nonce_s: bytes = base64.b64encode(s=cipher.encrypt(nonce_s.to_bytes(32, sys.byteorder, signed=False)))
        hash_a_content: bytes = f"{self.__pseudonym}{self.__other_pseudonym}{nonce_a}{nonce_b}{nonce_s}{dh_modulus_a}{dh_modulus_b}".encode()
        hash_a: bytes = hashlib.sha256(string=hash_a_content).hexdigest().encode()
        signature_a: bytes = base64.b64encode(s=self.__private_key.sign(data=hash_a,
                                                                        signature_algorithm=ec.ECDSA(hashes.SHA256())))
        debug_msg = "MESSAGE 3 A -> B:\n\tDH_MODULUS A: {0}\n\tNONCE S: {1}\n\tSHARED KEY: {2}\n\tENCRYPTED NONCE S: {3}\n\tHASH A: {4}\n\tSIGNATURE A: {5}\n"
        debug(txt=debug_msg, params=[dh_modulus_a, nonce_s, self.__shared_key, enc_nonce_s, hash_a, signature_a], flag=self.debug_mode)
        self.__conn.send(f"{dh_modulus_a}>".encode() + enc_nonce_s + ">".encode() + signature_a)
        msg = self.__conn.recv(96)
        if msg == b"Error":
            return
        signature_b: bytes = msg.decode("utf-8")
        hash_b_content: str = f"{self.__pseudonym}{self.__other_pseudonym}{nonce_a}{nonce_b}{nonce_s}{self.__shared_key}"
        hash_b: bytes = hashlib.sha256(string=hash_b_content.encode()).hexdigest().encode()
        try:
            certificate_b.public_key().verify(signature=base64.b64decode(s=signature_b),
                                              data=hash_b,
                                              signature_algorithm=ec.ECDSA(hashes.SHA256()))
        except Exception:
            print(f"{self.__pseudonym}: Signature verification failed.")
            self.__authenticated = False
            return
        self.__authenticated = True

    def __authenticate(self) -> None:
        msg = self.__conn.recv(625)
        data = msg.decode("utf-8").split('>')
        self.__other_pseudonym: str = data[0]
        certificate_a: Certificate = x509.load_pem_x509_certificate(data=data[1].encode())
        self.__nonce = nonce_a = int(data[2])
        nonce_b: int = secrets.randbits(32)
        dhe: pyDHE.DHE = pyDHE.new()
        dh_modulus_b: int = dhe.getPublicKey()
        certificate_str = self.__certificate.replace('\n', '\n\t')
        debug_msg = "MESSAGE 2 B-> A:\n\tPSEUDONYM B: {0}\n\t" + f"CERTIFICATE B:\n\t{certificate_str}" + "NONCE B: {1}\n\tDH_MODULUS B: {2}\n"
        debug(txt=debug_msg, params=[self.__pseudonym, nonce_a, dh_modulus_b], flag=self.debug_mode)
        self.__conn.send(f"{self.__pseudonym}>{self.__certificate}>{nonce_b}>{dh_modulus_b}>".encode())
        msg = self.__conn.recv(759)
        data = msg.decode("utf-8").split('>')
        dh_modulus_a: int = int(data[0])
        enc_nonce_s: bytes = data[1].encode()
        signature_a: str = data[2]
        self.__shared_key: int = dhe.update(B=dh_modulus_a)
        cipher = self.__generate_cipher(self.__shared_key, nonce_a)
        nonce_s: int = int.from_bytes(bytes=cipher.decrypt(base64.b64decode(s=enc_nonce_s)),
                                      byteorder=sys.byteorder,
                                      signed=False)
        hash_a_content: str = f"{self.__other_pseudonym}{self.__pseudonym}{nonce_a}{nonce_b}{nonce_s}{dh_modulus_a}{dh_modulus_b}"
        hash_a = hashlib.sha256(string=hash_a_content.encode()).hexdigest().encode()
        try:
            certificate_a.public_key().verify(signature=base64.b64decode(s=signature_a),
                                              data=hash_a,
                                              signature_algorithm=ec.ECDSA(hashes.SHA256()))
        except Exception:
            debug_msg = "MESSAGE 3 VERIFICATION:\n\tNONCE S: {0}\n\tSHARED KEY: {1}\n\tENCRYPTED NONCE S: {2}\n\tEXPECTED HASH A: {3}\n"
            debug(txt=debug_msg, params=[nonce_s, self.__shared_key, enc_nonce_s, hash_a], flag=self.debug_mode)
            print(f"{self.__pseudonym}: Signature verification failed.")
            self.__authenticated = False
            self.__conn.send(b"Error")
            return
        hash_b_content: str = f"{self.__other_pseudonym}{self.__pseudonym}{nonce_a}{nonce_b}{nonce_s}{self.__shared_key}"
        hash_b: bytes = hashlib.sha256(string=hash_b_content.encode()).hexdigest().encode()
        signature_b: bytes = base64.b64encode(s=self.__private_key.sign(data=hash_b,
                                                                        signature_algorithm=ec.ECDSA(hashes.SHA256())))
        debug_msg = "MESSAGE 4 B-> A:\n\tNONCE S: {0}\n\tSHARED KEY: {1}\n\tSIGNATURE B: {2}\n"
        debug(txt=debug_msg, params=[nonce_s, self.__shared_key, signature_b], flag=self.debug_mode)
        self.__conn.send(signature_b)
        self.__authenticated = True

    def __generate_certificate(self, private_key: ec.EllipticCurvePrivateKey) -> str:
        subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                             x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lazio"),
                             x509.NameAttribute(NameOID.LOCALITY_NAME, "Roma"),
                             x509.NameAttribute(NameOID.PSEUDONYM, f"{self.__pseudonym}")])
        issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lazio"),
                            x509.NameAttribute(NameOID.LOCALITY_NAME, "Roma"),
                            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ministero dei Trasporti")])
        cert = x509.CertificateBuilder(subject_name=subject,
                                       issuer_name=issuer,
                                       public_key=private_key.public_key(),
                                       serial_number=x509.random_serial_number(),
                                       not_valid_before=datetime.datetime.utcnow(),
                                       not_valid_after=datetime.datetime.utcnow() + datetime.timedelta(hours=1))
        signed_cert = cert.sign(private_key=private_key,
                                algorithm=hashes.SHA256())
        return signed_cert.public_bytes(serialization.Encoding.PEM).decode()

    def __generate_cipher(self, shared_key, nonce) -> ChaCha20:
        return ChaCha20.new(key=shared_key.to_bytes(length=256,
                                                    byteorder=sys.byteorder,
                                                    signed=False)[224:],
                            nonce=nonce.to_bytes(length=256,
                                                 byteorder=sys.byteorder,
                                                 signed=False)[232:])

    def is_authenticated(self):
        return self.__authenticated

    def get_private_key(self):
        return self.__private_key
