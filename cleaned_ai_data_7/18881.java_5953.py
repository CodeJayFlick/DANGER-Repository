import typing as t

class PersistVersionStoreExtension:
    database_adapter: t.Optional[t.Callable[[], 'DatabaseAdapter']] = None

    @classmethod
    def for_database_adapter(cls, database_adapter: t.Callable[[], 'DatabaseAdapter']) -> 'PersistVersionStoreExtension':
        cls.database_adapter = database_adapter
        return cls()

class DatabaseAdapter:
    pass  # Replace with actual implementation

def after_beans_discovery(abd: t.Any, bm: t.Any) -> None:
    store_worker = TableCommitMetaStoreWorker()  # Replace with actual implementation

    abd.addBean().add_type(VersionStore).scope(ApplicationScoped()).produce_with(lambda: PersistVersionStore(database_adapter.get(), store_worker))

class ApplicationScoped:
    pass  # Replace with actual implementation

class VersionStore(t.Generic):
    def __init__(self, database_adapter: DatabaseAdapter, store_worker: 'TableCommitMetaStoreWorker'):
        self.database_adapter = database_adapter
        self.store_worker = store_worker

class TableCommitMetaStoreWorker:
    pass  # Replace with actual implementation

class CommitMeta:
    pass  # Replace with actual implementation

class Contents(t.Generic):
    def __init__(self, type: 'Type'):
        self.type = type

class Type:
    pass  # Replace with actual implementation
