import ssl
import os
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives.asymmetric import x509 as asym_x509
from cryptography.hazmat.backends import default_backend

class ApplicationTrustManagerFactory:
    GHIDRA_CACERTS_PATH_PROPERTY = "ghidra.cacerts"

    trust_manager = None
    wrapped_trust_managers = []
    has_cas = False
    ca_error = None

    def __init__(self):
        pass  # no instantiation - static methods only

    @staticmethod
    def init():
        if not ApplicationTrustManagerFactory.wrapped_trust_managers:
            ApplicationTrustManagerFactory.wrapped_trust_managers = [WrappedTrustManager()]

        cacerts_path = os.environ.get(ApplicationTrustManagerFactory.GHIDRA_CACERTS_PATH_PROPERTY)
        if cacerts_path is None or len(cacerts_path) == 0:
            # check user preferences if cacerts not set via system property
            cacerts_path = Preferences().get_property(ApplicationTrustManagerFactory.GHIDRA_CACERTS_PATH_PROPERTY)
            if cacerts_path is None or len(cacerts_path) == 0:
                Msg.info("Trust manager disabled, cacerts have not been set")
                ApplicationTrustManagerFactory.trust_manager = OpenTrustManager()
                return

        try:
            Msg.info(f"Trust manager initializing with cacerts: {cacerts_path}")
            key_store = ApplicationKeyStore().get_certificate_store_instance(cacerts_path)
            trust_manager_factory = ssl.TrustManagerFactory.getInstance(ssl.get_default_algorithm())
            trust_manager_factory.init(key_store)
            trust_managers = trust_manager_factory.get_trust_managers()
            for tm in trust_managers:
                if isinstance(tm, asym_x509.X509TrustManager):
                    ApplicationKeyStore().log_certs(tm.get_accepted_issuers())
                    ApplicationTrustManagerFactory.trust_manager = tm
                    break

            ApplicationTrustManagerFactory.has_cas = True
        except (ssl.GeneralSecurityException, ssl.IOError) as e:
            ca_error = e
            msg = str(e)
            if msg is None:
                msg = str(e)

            Msg.error(f"Failed to process cacerts ({cacerts_path}): {msg}", e)

    @staticmethod
    def has_certificate_authorities():
        return ApplicationTrustManagerFactory.has_cas

    @staticmethod
    def has_cert_error():
        return ApplicationTrustManagerFactory.ca_error is not None

    @staticmethod
    def get_cert_error():
        return ApplicationTrustManagerFactory.ca_error

    @staticmethod
    def get_trust_managers():
        if ApplicationTrustManagerFactory.trust_manager is None:
            ApplicationTrustManagerFactory.init()

        return [tm.clone() for tm in ApplicationTrustManagerFactory.wrapped_trust_managers]

    @staticmethod
    def invalidate_trust_managers():
        ApplicationTrustManagerFactory.trust_manager = None
        ApplicationTrustManagerFactory.ca_error = None


class WrappedTrustManager(asym_x509.X509TrustManager):
    def check_client_trusted(self, chain: list[Certificate], auth_type: str) -> None:
        if ApplicationTrustManagerFactory.trust_manager is None:
            raise ssl.CertificateException("Trust manager not properly initialized")

        ApplicationTrustManagerFactory.trust_manager.check_client_trusted(chain, auth_type)

    def check_server_trusted(self, chain: list[Certificate], auth_type: str) -> None:
        if ApplicationTrustManagerFactory.trust_manager is None:
            raise ssl.CertificateException("Trust manager not properly initialized")

        ApplicationTrustManagerFactory.trust_manager.check_server_trusted(chain, auth_type)

    def get_accepted_issuers(self) -> list[Certificate]:
        if ApplicationTrustManagerFactory.trust_manager is None:
            return []

        return ApplicationTrustManagerFactory.trust_manager.get_accepted_issuers()


class OpenTrustManager(asym_x509.X509TrustManager):
    def check_client_trusted(self, chain: list[Certificate], auth_type: str) -> None:
        # trust all certs
        pass

    def check_server_trusted(self, chain: list[Certificate], auth_type: str) -> None:
        # trust all certs
        pass

    def get_accepted_issuers(self) -> list[Certificate]:
        return []
