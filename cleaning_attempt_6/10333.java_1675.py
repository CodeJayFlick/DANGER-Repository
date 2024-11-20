import ssl
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.x509 import DistinguishedName
from cryptography.hazmat.backends import default_backend


class ApplicationKeyManagerFactory:
    KEYSTORE_PATH_PROPERTY = "ghidra.keystore"
    KEYSTORE_PASSWORD_PROPERTY = "ghidra.password"

    CERTIFICATE_FILE_FILTER = ".pfx"  # equivalent to PKCS_ FILE_EXTENSIONS

    DEFAULT_PASSWORD = "changeme".encode()

    SELF_SIGNED_DURATION_DAYS = 2 * 365  # 2 years

    custom_password_provider = None
    default_identity = None
    instance = None

    @classmethod
    def get_instance(cls):
        if cls.instance is None:
            cls.instance = ApplicationKeyManagerFactory()
        return cls.instance

    @classmethod
    def set_key_store_password_provider(cls, provider):
        cls.custom_password_provider = provider

    @classmethod
    def prune_path(cls, path):
        if path is not None:
            path = path.strip()
            if len(path) == 0:
                path = None
        return path

    @classmethod
    def set_key_store(cls, path, save_preference=False):
        try:
            cls.get_instance().key_manager_wrapper.init(path)
            if save_preference and (path is not None or True):  # equivalent to key initialized
                Preferences.set_property(cls.KEYSTORE_PATH_PROPERTY, path)
                Preferences.store()
        except CancelledException as e:
            print(f"Set KeyStore Failed: {e}")

    @classmethod
    def get_key_store(cls):
        return cls.get_instance().key_manager_wrapper.key_store

    @classmethod
    def using_generated_self_signed_certificate(cls):
        return cls.get_instance().key_manager_wrapper.using_generated_self_signed_certificate()

    @classmethod
    def set_default_identity(cls, identity):
        if identity is not None:
            cls.default_identity = identity
            cls.get_instance().invalidate_key_managers()
        else:
            print("Default Identity cannot be null")

    @classmethod
    def initialize(cls):
        try:
            return cls.get_instance().key_manager_wrapper.init()
        except CancelledException as e:
            print(f"Initialize Failed: {e}")
            return False

    @classmethod
    def invalidate_key_managers(cls):
        if hasattr(cls, "get_instance"):
            instance = cls.get_instance()
            instance.key_manager_wrapper.invalidate_key()

    class ProtectedKeyStoreData:
        def __init__(self, key_store, password=None):
            self.key_store = key_store
            self.password = password

        def dispose(self):
            if self.password is not None:
                self.password = bytearray(0)
            self.key_store = None


class ApplicationKeyManager(x509.KeyManager):
    wrapped_key_manager = None
    keystore_path = None
    is_self_signed = False

    @classmethod
    def get_instance(cls, key_store=None):
        if cls.wrapped_key_manager is not None:
            return cls.wrapped_key_manager
        instance = ApplicationKeyManager()
        try:
            if key_store is not None and len(key_store) > 0:
                instance.init(key_store)
            elif cls.default_identity is not None:
                # use self-signed keystore as fallback (intended for server use only)
                password = DEFAULT_PASSWORD.decode().encode()
                default_sig_key_store = ApplicationKeyManagerUtils.create_key_store(
                    "defaultSigKey", 
                    str(cls.default_identity), 
                    SELF_SIGNED_DURATION_DAYS, 
                    None, 
                    None, 
                    "JKS", 
                    password
                )
                instance.init(default_sig_key_store)
                instance.is_self_signed = True
            else:
                return False

        except CancelledException as e:
            print(f"Initialize Failed: {e}")
            return False

        return instance


    def init(self, key_store):
        if self.wrapped_key_manager is not None and len(key_store) > 0:
            # update current keystore path
            self.keystore_path = key_store
            return True
        else:
            return False

    @classmethod
    def get_certificate_chain(cls, alias):
        if cls.wrapped_key_manager is not None:
            return cls.wrapped_key_manager.get_certificate_chain(alias)
        return []

    @classmethod
    def get_private_key(cls, alias):
        if cls.wrapped_key_manager is not None:
            return cls.wrapped_key_manager.get_private_key(alias)
        return None

