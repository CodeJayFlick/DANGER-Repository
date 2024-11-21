import os
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.x509 import DistinguishedName
from cryptography.hazmat.backends import default_backend
from datetime import datetime

class ApplicationKeyStore:
    PKCS_FILE_EXTENSIONS = ["p12", "pks", "pfx"]

    @staticmethod
    def get_certificate_store_instance(cacerts_path):
        try:
            with open(cacerts_path, 'rb') as f:
                certificate_pem = f.read()
                certificates = x509.load_der_x509_certificates(certificate_pem)
                
                store = {}
                for cert in certificates:
                    name = DistinguishedName(*cert.subject).common_name
                    if isinstance(cert, x509.Certificate):
                        store[name] = cert.public_bytes(x509.Form.DER)

            return store

        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def get_key_store_instance(keystore_path, password=None):
        try:
            with open(keystore_path, 'rb') as f:
                keystore_pem = f.read()
                
                if "PKCS12" in keystore_path or "pks" in keystore_path or "pfx" in keystore_path:
                    store = x509.load_der_x509_certificates(keystore_pem)
                else:
                    store = {}
                    
            return store

        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def get_common_name(subject):
        try:
            name = str(subject).split(",")[0].strip()
            
            equals_index = name.find("=")
            if equals_index <= 0:
                return name
            
            field_name = name[:equals_index].strip()
            field_value = name[equals_index + 1:].strip()

            if not field_name.lower() == "cn":
                return name

            return field_value

        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def log_certs(key_store):
        try:
            for alias in key_store.keys():
                certificate = x509.load_der_x509_certificates([key_store[alias]])[0]
                
                if isinstance(certificate, x509.Certificate):
                    ApplicationKeyStore.log_cert(alias, certificate)

        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def log_cert(alias, cert):
        try:
            subject = DistinguishedName(*cert.subject)
            issuer = DistinguishedName(*cert.issuer)
            
            now = datetime.now()
            if now > cert.not_after:
                print(f"{alias}: {subject.common_name}, issued by {issuer.common_name}, S/N {cert.serial_number.hex()}, expired {cert.not_after}")
            else:
                print(f"{alias}: {subject.common_name}, issued by {issuer.common_name}, S/N {cert.serial_number.hex()}, expires {cert.not_after}")

        except Exception as e:
            print(f"Error: {e}")


# Example usage
cacerts_path = "path_to_your_cacert.pem"
keystore_path = "path_to_your_keystore.p12"

store = ApplicationKeyStore.get_certificate_store_instance(cacerts_path)
ApplicationKeyStore.log_certs(store)

ks = ApplicationKeyStore.get_key_store_instance(keystore_path, password="your_password")
ApplicationKeyStore.log_certs(ks)
