class RocksVersionStoreFactory:
    def __init__(self):
        self.rocks_db_instance = None
        self.config = None

    @property
    def rocks_db_instance(self):
        return self._rocks_db_instance

    @rocks_db_instance.setter
    def rocks_db_instance(self, value):
        self._rocks_db_instance = value

    @property
    def config(self):
        return self._config

    @config.setter
    def config(self, value):
        self._config = value

    def new_store(self, worker: 'StoreWorker', server_config: dict) -> 'VersionStore':
        database_adapter = RocksDatabaseAdapterFactory().new_builder() \
            .with_config(self.config) \
            .with_connector(self.rocks_db_instance) \
            .build()

        database_adapter.initialize_repo(server_config.get('default_branch'))

        return PersistVersionStore(database_adapter, worker)


class StoreWorker:
    pass


class VersionStore:
    pass


class RocksDatabaseAdapterFactory:
    def new_builder(self):
        pass

    def build(self):
        pass
