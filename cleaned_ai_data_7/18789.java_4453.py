import abc

class HttpCommitMultipleOperations(metaclass=abc.ABCMeta):
    def __init__(self, client):
        self.client = client
        self.operations = ImmutableOperations()

    @property
    def operations(self):
        return self._operations

    @operations.setter
    def operations(self, value):
        self._operations = value

    def commit_meta(self, commit_meta):
        self.operations.commit_meta(commit_meta)
        return self

    def operations(self, operations: list) -> 'HttpCommitMultipleOperations':
        self.operations.addAllOperations(operations)
        return self

    def operation(self, operation: Operation) -> 'HttpCommitMultipleOperations':
        self.operations.addOperation(operation)
        return self

    def commit(self) -> Branch:
        try:
            return self.client.get_tree_api().commit_multiple_operations(
                branch_name=self.branch_name,
                hash=self.hash,
                operations=self.operations.build()
            )
        except NessieNotFoundException as e:
            raise
        except NessieConflictException as e:
            raise

class ImmutableOperations(metaclass=abc.ABCMeta):
    def __init__(self, *args, **kwargs):
        pass  # not implemented in this example

    @property
    def build(self) -> 'ImmutableOperations':
        return self._build()

    @build.setter
    def build(self, value: ImmutableOperations):
        self._build = value

class Operation(metaclass=abc.ABCMeta):
    pass  # abstract class not implemented in this example

# Example usage:
client = NessieApiClient()
http_commit_multiple_operations = HttpCommitMultipleOperations(client)
branch_name = "my_branch"
hash = "my_hash"

try:
    branch = http_commit_multiple_operations.commit(branch_name, hash)
except NessieNotFoundException as e:
    print(f"Error: {e}")
except NessieConflictException as e:
    print(f"Error: {e}")

print(f"Committed to branch {branch_name} with commit hash {hash}")
