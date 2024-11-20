import pickle
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.x509 import load_pem_x509_certificate

class SignatureCallback:
    def __init__(self, recognized_authorities: list, token: bytes, server_signature: bytes):
        self.recognized_authorities = recognized_authorities
        self.token = token
        self.server_signature = server_signature
        self.signature = None
        self.cert_chain = []

    @property
    def recognized_authorities(self) -> list:
        return self._recognized_authorities

    @recognized_authorities.setter
    def recognized_authorities(self, value: list):
        if not isinstance(value, list):
            raise ValueError("Recognized authorities must be a list")
        self._recognized_authorities = value

    @property
    def token(self) -> bytes:
        return self._token

    @token.setter
    def token(self, value: bytes):
        if not isinstance(value, bytes):
            raise ValueError("Token must be bytes")
        self._token = value

    @property
    def signature(self) -> bytes:
        return self._signature

    @signature.setter
    def signature(self, value: bytes):
        if not isinstance(value, bytes):
            raise ValueError("Signature must be bytes")
        self._signature = value

    @property
    def cert_chain(self) -> list:
        return self._cert_chain

    @cert_chain.setter
    def cert_chain(self, value: list):
        if not all(isinstance(x509_cert, x509.Certificate) for x509_cert in value):
            raise ValueError("Certificate chain must be a list of X.509 certificates")
        self._cert_chain = value

    def sign(self, sig_cert_chain: list, cert_signature: bytes):
        self.cert_chain = sig_cert_chain
        if not isinstance(cert_signature, bytes):
            raise ValueError("Signature must be bytes")
        self.signature = cert_signature


# Example usage:
recognized_authorities = [load_pem_x509_certificate(pem_bytes).subject]
token = b'random_token'
server_signature = b'server_signature'

callback = SignatureCallback(recognized_authorities, token, server_signature)
print(callback.recognized_authorities)  # prints the recognized authorities
print(callback.token)  # prints the token
print(callback.signature)  # prints None (since it hasn't been signed yet)

# Sign the token using a certificate chain and signature:
cert_chain = [load_pem_x509_certificate(pem_bytes)]
signature = b'signed_token'
callback.sign(cert_chain, signature)
print(callback.cert_chain)  # prints the certificate chain
print(callback.signature)  # prints the signed token

