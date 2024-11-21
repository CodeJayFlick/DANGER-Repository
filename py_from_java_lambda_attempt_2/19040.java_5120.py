Here is the translation of the Java code into Python:

```Python
class InMemoryDatabaseAdapter:
    def __init__(self, config: 'NonTransactionalDatabaseAdapterConfig', store):
        self.store = store
        self.key_prefix = ByteString(config.get_key_prefix() + ':').to_bytes()

    @staticmethod
    def db_key(hash) -> bytes:
        return InMemoryDatabaseAdapter.key_prefix + hash.as_bytes()

    @staticmethod
    def db_key(key: 'ByteString') -> bytes:
        return InMemoryDatabaseAdapter.key_prefix + key

    def reinitialize_repo(self, default_branch_name):
        self.store.reinitialize_repo(InMemoryDatabaseAdapter.key_prefix)
        super().reinitialize_repo(default_branch_name)

    def fetch_global_pointer(self, ctx) -> 'GlobalStatePointer':
        return self.global_state.get()

    def write_individual_commit(self, ctx: 'NonTransactionalOperationContext', entry: 'CommitLogEntry'):
        if not self.store.commit_log.put_if_absent(InMemoryDatabaseAdapter.db_key(entry.hash), to_proto(entry).to_bytes()):
            raise ReferenceConflictException

    def write_multiple_commits(self, ctx: 'NonTransactionalOperationContext', entries):
        for entry in entries:
            self.write_individual_commit(ctx, entry)

    def write_global_commit(self, ctx: 'NonTransactionalOperationContext', entry: 'GlobalStateLogEntry'):
        if not self.store.global_state_log.put_if_absent(InMemoryDatabaseAdapter.db_key(entry.id), entry.to_bytes()):
            raise ReferenceConflictException

    def unsafe_write_global_pointer(self, ctx: 'NonTransactionalOperationContext', pointer):
        self.global_state.set(pointer)

    def global_pointer_cas(self, ctx: 'NonTransactionalOperationContext', expected, new_pointer) -> bool:
        return self.global_state.compare_and_set(expected, new_pointer)

    @property
    def global_state(self) -> 'AtomicReference[GlobalStatePointer]':
        return self.store.global_state_pointer.compute_if_absent(InMemoryDatabaseAdapter.key_prefix, lambda k: AtomicReference(None))

    def clean_up_commit_cas(self, ctx: 'NonTransactionalOperationContext', global_id: Hash, branch_commits: Set[Hash], new_key_lists: Set[Hash]):
        if global_id in self.store.global_state_log:
            del self.store.global_state_log[InMemoryDatabaseAdapter.db_key(global_id)]
        for h in branch_commits:
            if h in self.store.commit_log:
                del self.store.commit_log[InMemoryDatabaseAdapter.db_key(h)]
        for h in new_key_lists:
            if h in self.store.key_lists:
                del self.store.key_lists[InMemoryDatabaseAdapter.db_key(h)]

    def fetch_from_global_log(self, ctx: 'NonTransactionalOperationContext', id) -> 'GlobalStateLogEntry':
        serialized = self.store.global_state_log.get(InMemoryDatabaseArray.db_key(id))
        if serialized is not None:
            try:
                return GlobalStateLogEntry.parse(serialized)
            except InvalidProtocolBufferException as e:
                raise RuntimeError(e)

    def fetch_page_from_global_log(self, ctx: 'NonTransactionalOperationContext', hashes) -> List['GlobalStateLogEntry']:
        return [self.fetch_from_global_log(ctx, h) for h in hashes]

    def fetch_from_commit_log(self, ctx: 'NonTransactionalOperationContext', hash) -> 'CommitLogEntry':
        serialized = self.store.commit_log.get(InMemoryDatabaseAdapter.db_key(hash))
        if serialized is not None:
            try:
                return proto_to_commit_log_entry(serialized)
            except InvalidProtocolBufferException as e:
                raise RuntimeError(e)

    def fetch_page_from_commit_log(self, ctx: 'NonTransactionalOperationContext', hashes) -> List['CommitLogEntry']:
        return [self.fetch_from_commit_log(ctx, h) for h in hashes]

    def write_key_list_entities(self, ctx: 'NonTransactionalOperationContext', new_key_list_entities):
        for e in new_key_list_entities:
            self.store.key_lists.put(InMemoryDatabaseAdapter.db_key(e.id), to_proto(e.keys).to_bytes())

    def fetch_key_lists(self, ctx: 'NonTransactionalOperationContext', key_lists_ids) -> Stream['KeyListEntity']:
        return (lambda h: [self.fetch_from_commit_log(ctx, h)] for h in key_lists_ids)

    @staticmethod
    def entity_size(entry):
        return to_proto(entry).get_serialized_size()

class NonTransactionalDatabaseAdapterConfig:
    # todo implement this class

class GlobalStatePointer:
    # todo implement this class

class CommitLogEntry:
    # todo implement this class

class KeyListEntity:
    # todo implement this class
```

Please note that the Python code above is not a direct translation of Java to Python. It's more like an adaptation, as some concepts and classes are different in both languages.