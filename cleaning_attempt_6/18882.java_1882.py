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

