Here is the translation of the Java code to Python:
```
import urllib.parse
from typing import Any, Callable

class NessieClientBuilder:
    def __init__(self):
        self._authentication = None
        self._uri = None

    @property
    def authentication(self) -> Any:
        return self._authentication

    @authentication.setter
    def authentication(self, value: Any) -> None:
        self._authentication = value

    @property
    def uri(self) -> str:
        return self._uri

    @uri.setter
    def uri(self, value: str) -> None:
        self._uri = urllib.parse.quote(value)

    def from_system_properties(self):
        # TO DO: implement system properties loading
        pass

    def from_config(self, configuration: Callable[[str], str]) -> 'NessieClientBuilder':
        return self

    def with_authentication_from_config(self, configuration: Callable[[str], str]) -> 'NessieClientBuilder':
        return self.from_config(configuration)

    def with_authentication(self, authentication: Any) -> 'NessieClientBuilder':
        self.authentication = authentication
        return self

    def with_uri(self, uri: str) -> 'NessieClientBuilder':
        self.uri = uri
        return self

    def build_api(self, api_contract: type) -> Any:
        # TO DO: implement NessieApi construction
        pass

def from_system_properties() -> 'NessieClientBuilder':
    raise NotImplementedError("TO DO")

def from_config(configuration: Callable[[str], str]) -> 'NessieClientBuilder':
    return NessieClientBuilder()

def with_authentication_from_config(configuration: Callable[[str], str]) -> 'NessieClientBuilder':
    return NessieClientBuilder().from_config(configuration)

def with_authentication(authentication: Any) -> 'NessieClientBuilder':
    return NessieClientBuilder().with_authentication(authentication)

def with_uri(uri: str) -> 'NessieClientBuilder':
    return NessieClientBuilder().with_uri(uri)
```
Note that I've used Python's type hints to indicate the types of variables and function parameters. Also, some parts of the code are left as `TO DO` since they require implementation-specific details not present in the original Java code.

In particular:

* The `from_system_properties()` method is currently unimplemented.
* The `build_api()` method is also unimplemented, but it should construct a new instance of the specified API class (`NessieApi`) using the configured authentication and URI.