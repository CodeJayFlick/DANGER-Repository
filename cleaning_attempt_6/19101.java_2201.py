import abc

class H2TestConnectionProviderSource(abc.ABC):
    def __init__(self):
        pass

    @classmethod
    def is_compatible(cls, adapter_config: 'DatabaseAdapterConfig', database_adapter_factory: 'DatabaseAdapterFactory') -> bool:
        return isinstance(adapter_config, TxDatabaseAdapterConfig) and isinstance(database_adapter_factory, H2DatabaseAdapterFactory)

    @abc.abstractmethod
    def create_default_connection_provider_config(self) -> 'LocalTxConnectionConfig':
        pass

    @abc.abstractmethod
    def create_connection_provider(self) -> 'LocalConnectionProvider':
        pass

    def start(self):
        self.configure_connection_provider_config_from_defaults(lambda c: c.with_jdbc_url("jdbc:h2:mem:nessie"))
        super().start()
