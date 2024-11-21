class DatabaseAdapterFactory:
    def __init__(self):
        pass

    @property
    def new_builder(self) -> 'Builder':
        return Builder()

    @property
    def name(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    class Builder:
        def __init__(self, config: object = None, connector: object = None):
            self.config = config
            self.connector = connector

        def with_config(self, config: object) -> 'Builder':
            self.config = config
            return self

        def with_connector(self, connector: object) -> 'Builder':
            self.connector = connector
            return self

        @abstractmethod
        def get_default_config(self) -> object:
            pass

        @abstractmethod
        def adjustable_config(self, config: object) -> object:
            pass

        @property
        def config(self) -> object:
            if not self.config:
                self.config = self.get_default_config()
            return self.config

        @property
        def connector(self) -> object:
            return self.connector

        @abstractmethod
        def build(self) -> object:
            pass

        def configure(self, configurator: callable) -> 'Builder':
            if not self.config:
                self.config = configurator(adjustable_config(self.get_default_config()))
            return self


def load_factory_by_name(name: str) -> DatabaseAdapterFactory:
    return load_factory(lambda x: x.name.lower() == name)


def load_factory(check: callable) -> DatabaseAdapterFactory:
    for factory in ServiceLoader.load(DatabaseAdapterFactory):
        if check(factory):
            return factory
    raise ValueError("No DatabaseAdapterFactory passed the given predicate.")
