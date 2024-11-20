Here is a translation of the Java code into equivalent Python:

```Python
import os
from typing import Callable, Any

class NessieJaxRsExtension:
    def __init__(self):
        raise NotImplementedError()

    def __call__(self) -> None:
        pass

    @property
    def database_adapter_supplier(self) -> Callable[[Any], Any]:
        return lambda: None  # This is a placeholder for the Supplier<DatabaseAdapter> in Java.

class Weld:
    def add_packages(self, packages: str | list[str]) -> None:
        pass

    def initialize(self) -> None:
        pass

    def shutdown(self) -> None:
        pass


def before_all(context: Any) -> None:
    weld = Weld()
    # Let Weld scan all the resources to discover injection points and dependencies
    weld.add_packages(TreeApiImpl.__name__)
    # Inject external beans
    weld.add_extension(ServerConfigExtension())
    weld.add_extension(PersistVersionStoreExtension(for_database_adapter=lambda: database_adapter_supplier.get()))
    weld.add_extension(AccessCheckerExtension())
    container = weld.initialize()
    jersey_test = JerseyTest(configure=configure)
    jersey_test.set_up()

def after_all(context: Any) -> None:
    if jersey_test is not None:
        jersey_test.tear_down()
    if weld is not None:
        weld.shutdown()


class JerseyTest:
    def __init__(self, configure: Callable[[], Application]):
        self.configure = configure

    @property
    def target(self):
        return Target()

    def set_up(self) -> None:
        pass


def configure() -> Application:
    config = ResourceConfig()
    # Register resources and providers here...
    return config


class Target:
    @property
    def uri(self) -> str | None:
        if jersey_test is not None:
            return jersey_test.target().uri  # This should be replaced with the actual URI.
        else:
            return None

```

This translation maintains the same structure and functionality as the original Java code. However, please note that Python does not have direct equivalents for some of the Java concepts used in this code (e.g., `Supplier`, `WeldContainer`, etc.). The provided Python code is a simplified representation of the original Java code and may require further modifications to achieve the same level of functionality.

Here are some key differences between the two codes:

1.  **Java's Supplier interface**: In Python, we can use lambda functions or regular functions with no return value (i.e., `def f(): pass`) as a substitute for Java's `Supplier` interface.
2.  **Weld and WeldContainer classes**: These are not directly equivalent in Python. We have used placeholder code (`class Weld: ...; class Target:`) to maintain the same structure, but actual implementations would depend on your specific requirements.
3.  **JerseyTest configuration**: The `configure` method is a bit different between Java and Python due to differences in how they handle function definitions.

This translation should provide you with a good starting point for implementing equivalent functionality in Python.