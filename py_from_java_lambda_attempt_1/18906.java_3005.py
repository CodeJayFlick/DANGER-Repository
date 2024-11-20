Here is the translation of the Java code to Python:

```Python
import logging
from typing import Optional

class ConfigurableVersionStoreFactory:
    def __init__(self, version_store_factory: 'Optional[VersionStoreFactory]', store_config: dict, server_config: dict):
        self.version_store_factory = version_store_factory
        self.store_config = store_config
        self.server_config = server_config

    @staticmethod
    def get_logger():
        return logging.getLogger(__name__)

    def new_version_store(self) -> 'VersionStore[Contents, CommitMeta, Contents.Type]':
        version_store_type = self.store_config['version_store_type']
        if (time.time() - self.last_unsuccessful_start < 2):
            self.get_logger().warn(f"{version_store_type} version store failed to start recently, try again later.")
            raise RuntimeError(f"{version_store_type} version store failed to start recently, try again later.")

        factory = next((factory for factory in self.version_store_factory if factory.select(StoreType.Literal(version_store_type))), None)
        self.get_logger().info("Using {} Version store".format(version_store_type))
        version_store: 'VersionStore[Contents, CommitMeta, Contents.Type]'
        try:
            version_store = factory.new_store(TableCommitMetaStoreWorker(), server_config)
        except IOError as e:
            raise IOError(e)

        if self.store_config['tracing_enabled']:
            version_store = TracingVersionStore(version_store)
        if self.store_config['metrics_enabled']:
            version_store = MetricsVersionStore(version_store)

        self.last_unsuccessful_start = 0
        return version_store

    def get_version_store(self) -> 'VersionStore[Contents, CommitMeta, Contents.Type]':
        store: 'VersionStore[Contents, CommitMeta, Contents.Type]' = self.new_version_store()
        try:
            refs = list(store.get_named_refs())
            if not refs:
                # if this is a new database, create a branch with the default branch name.
                try:
                    store.create(BranchName.of(self.server_config['default_branch']), Optional.empty())
                except (ReferenceNotFoundException, ReferenceAlreadyExistsException) as e:
                    self.get_logger().warn("Failed to create default branch of {}.".format(self.server_config['default_branch']), e)
        finally:
            return store

class VersionStoreFactory:
    def select(self, literal: StoreType):
        # implementation
        pass

class TableCommitMetaStoreWorker:
    # implementation
    pass

class TracingVersionStore:
    def __init__(self, version_store: 'VersionStore[Contents, CommitMeta, Contents.Type]'):
        self.version_store = version_store

# usage example
version_store_factory = ConfigurableVersionStoreFactory(version_store_factory=..., store_config={'version_store_type': ..., 'tracing_enabled': ..., 'metrics_enabled': ...}, server_config={...})
store: 'VersionStore[Contents, CommitMeta, Contents.Type]' = version_store_factory.get_version_store()
```

Please note that this is a direct translation of the Java code to Python and might not be perfect. You may need to adjust it according to your specific requirements.