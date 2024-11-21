class CryptoProviders:
    _singleton_instance = None

    def __new__(cls):
        if cls._singleton_instance is None:
            cls._singleton_instance = super().__new__(cls)
        return cls._singleton_instance

    def __init__(self):
        self.cached_crypto_provider = CachedPasswordProvider()
        self.crypto_providers = []

    @classmethod
    def get_instance(cls):
        return cls._singleton_instance

    def register_crypto_provider(self, provider):
        if isinstance(provider, CryptoProvider):
            self.crypto_providers.append(provider)

    def unregister_crypto_provider(self, provider):
        if isinstance(provider, CryptoProvider) and provider in self.crypto_providers:
            self.crypto_providers.remove(provider)

    @property
    def cached_crypto_provider(self):
        return self._cached_crypto_provider

    @cached_crypto_provider.setter
    def cached_crypto_provider(self, value):
        self._cached_crypto_provider = value


class CachedPasswordProvider:
    pass  # Implement this class as needed


def new_session(self):
    return CryptoSessionImpl(self.crypto_providers)


class CryptoSessionImpl(CryptoSession):
    def __init__(self, providers):
        super().__init__()
        self.providers = list(providers)
        self.session_state_values = {}
        self.closed = False

    def add_successful_password(self, fsrl, password):
        # Implement this method as needed
        pass

    def close(self):
        self.closed = True

    def is_closed(self):
        return self.closed


class CryptoSession:
    pass  # Implement this class as needed


def get_crypto_provider_instance(self, provider_class):
    for provider in self.crypto_providers:
        if isinstance(provider, provider_class):
            return provider
    return None


# Usage example:

crypto_providers = CryptoProviders()
cached_password_provider = CachedPasswordProvider()

crypto_session = crypto_providers.new_session()
