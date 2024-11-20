Here is the translation of the given Java code into equivalent Python:

```Python
from abc import ABC, abstractmethod


class CryptoProvider(ABC):
    @abstractmethod
    def get_session(self) -> 'CryptoSession':
        pass


class CryptoSession:
    def __init__(self, crypto_provider: CryptoProvider):
        self.crypto_provider = crypto_provider

    def set_state_value(self, value: object):
        # Saves a state object into the session using the cryptoprovider's identity as the key
        pass  # TO DO: implement this method

    def get_state_value(self) -> object:
        # Retrieves a state object from the session
        return None  # TO DO: implement this method

    def get_crypto_provider(self) -> CryptoProvider:
        # Returns the CryptoProviders instance that created this session.
        return self.crypto_provider


class Supplier(ABC):
    @abstractmethod
    def __call__(self) -> object:
        pass


# Note: Python does not have direct equivalent of Java's generic type system. 
# So, we can't directly translate the Session interface with a type parameter like in Java.

```

Please note that this translation is based on my understanding and may require adjustments according to your specific requirements or use cases.