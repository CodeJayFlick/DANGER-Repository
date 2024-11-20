class TestConnectionProviderSource:
    def __init__(self):
        pass

    @staticmethod
    def find_compatible_provider_source(adapter_config: 'DatabaseAdapterConfig', 
                                         factory: 'DatabaseAdapterFactory', provider_spec=None) -> 'TestConnectionProviderSource':
        compatible_providers = []
        for provider in ServiceLoader.load(TestConnectionProviderSource):
            if provider.is_compatible_with(adapter_config, factory):
                compatible_providers.append(provider)
        
        if not compatible_providers:
            raise ValueError(f"No matching TestConnectionProviderSource found for {adapter_config}")
        
        if provider_spec is not None:
            compatible_providers = [provider for provider in compatible_providers 
                                     if provider.__class__.__name__.lower().find(provider_spec) != -1]
        
        if len(compatible_providers) > 1:
            raise ValueError(f"Too many TestConnectionProviderSource instances matched: {', '.join(map(str, compatible_providers))}")
        
        return compatible_providers[0]

    def is_compatible_with(self, adapter_config: 'DatabaseAdapterConfig', factory: 'DatabaseAdapterFactory') -> bool:
        pass

    @abstractmethod
    def create_default_connection_provider_config(self) -> 'DatabaseConnectionConfig':
        pass

    def configure_connection_provider_config_from_defaults(self, configurer):
        pass

    def set_connection_provider_config(self, connection_provider_config: 'DatabaseConnectionConfig'):
        pass

    def get_connection_provider_config(self) -> 'DatabaseConnectionConfig':
        pass

    @abstractmethod
    def start(self) -> None:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass

    @abstractmethod
    def get_connection_provider(self) -> 'DatabaseConnectionProvider':
        pass


class DatabaseAdapterConfig:
    pass


class DatabaseAdapterFactory:
    pass


class DatabaseConnectionConfig:
    pass


class DatabaseConnectionProvider:
    pass
