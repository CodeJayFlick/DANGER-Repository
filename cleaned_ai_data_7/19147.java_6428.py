class CommitBuilder:
    def __init__(self, store):
        self.store = store
        self.operations = []
        self.metadata = None
        self.reference_hash = None
        self.from_latest = False

    def put(self, key: str, value) -> 'CommitBuilder':
        return self.add(Put(key, value))

    def add(self, operation: Operation) -> 'CommitBuilder':
        self.operations.append(operation)
        return self

    def delete(self, key: str) -> 'CommitBuilder':
        if not key:
            raise ValueError("Key cannot be empty")
        return self.add(Delete(key))

    def unchanged(self, key: str) -> 'CommitBuilder':
        if not key:
            raise ValueError("Key cannot be empty")
        return self.add(Unchanged(key))

    def with_metadata(self, metadata) -> 'CommitBuilder':
        self.metadata = metadata
        return self

    def from_reference(self, reference_hash: Hash) -> 'CommitBuilder':
        self.reference_hash = reference_hash
        self.from_latest = False
        return self

    def from_latest(self) -> 'CommitBuilder':
        self.from_latest = True
        return self

    def to_branch(self, branch_name: str) -> Hash:
        if not branch_name:
            raise ValueError("Branch name cannot be empty")
        reference = None if self.from_latest else self.reference_hash
        commit_hash = self.store.commit(branch_name, reference, self.metadata, self.operations)
        store_hash = self.store.to_hash(branch_name)
        assert store_hash == commit_hash
        return commit_hash

class Operation:
    def __init__(self):
        pass

class Put(Operation):
    def __init__(self, key: str, value):
        super().__init__()
        self.key = key
        self.value = value

class Delete(Operation):
    def __init__(self, key: str):
        super().__init__()
        self.key = key

class Unchanged(Operation):
    def __init__(self, key: str):
        super().__init__()
        self.key = key

class Hash:
    pass
