Here is the translation of the given Java code into equivalent Python:

```Python
class TxDatabaseAdapterFactory:
    def __init__(self):
        pass

    @abstractmethod
    def create(self, config: 'TxDatabaseAdapterConfig', connector) -> 'DatabaseAdapter':
        pass


class Builder(TxDatabaseAdapterFactory):
    def __init__(self):
        self.config = None
        self.connector = None

    def set_config(self, config):
        self.config = config

    def set_connector(self, connector):
        self.connector = connector

    @abstractmethod
    def get_default_config(self) -> 'TxDatabaseAdapterConfig':
        pass

    @abstractmethod
    def adjustable_config(self, config: 'TxDatabaseAdapterConfig') -> 'AdjustableTxDatabaseAdapterConfig':
        pass

    def build(self) -> 'DatabaseAdapter':
        return self.create(self.get_default_config(), self.connector)


class TxBuilder(Builder):
    def get_default_config(self) -> 'TxDatabaseAdapterConfig':
        from your_module import ImmutableAdjustableTxDatabaseAdapterConfig
        config = ImmutableAdjustableTxDatabaseAdapterConfig.builder().build()
        return config

    def adjustable_config(self, config: 'TxDatabaseAdapterConfig') -> 'AdjustableTxDatabaseAdapterConfig':
        from your_module import ImmutableAdjustableTxDatabaseAdapterConfig
        adjusted_config = ImmutableAdjustableTxDatabaseAdapterConfig.builder().from(config).build()
        return adjusted_config


class DatabaseAdapterFactory:
    @abstractmethod
    def new_builder(self) -> 'Builder':
        pass

# Example usage:

adapter_factory = TxDatabaseAdapterFactory()

builder = adapter_factory.new_builder()  # This will be an instance of TxBuilder
config = builder.get_default_config()
connector = get_your_connector_instance()
database_adapter = builder.set_config(config).set_connector(connector).build()
```

Please note that Python does not support Java's concept of abstract classes and methods. Instead, we use the `abstractmethod` decorator from the `functools` module to indicate that a method should be implemented by any subclass.

Also, in Python, you don't need to specify types for variables or function parameters like you do in Java.