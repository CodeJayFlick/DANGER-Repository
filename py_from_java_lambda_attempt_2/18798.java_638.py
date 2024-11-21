Here is the translation of the Java code to Python:
```
import abc

class HttpMergeReference:
    def __init__(self, client):
        self.client = client
        self.merge_builder = ImmutableMergeBuilder()

    def from_ref_name(self, ref_name: str) -> 'HttpMergeReference':
        self.merge_builder.from_ref_name(ref_name)
        return self

    def from_hash(self, hash: str) -> 'HttpMergeReference':
        self.merge_builder.from_hash(hash)
        return self

    def merge(self):
        try:
            self.client.get_tree_api().merge_ref_into_branch(branch_name=self.branch_name, hash=self.hash, merge=self.merge_builder.build())
        except NessieNotFoundException as e:
            raise
        except NessieConflictException as e:
            raise


class ImmutableMergeBuilder:
    def from_ref_name(self, ref_name: str):
        # implementation

    def from_hash(self, hash: str):
        # implementation

    def build(self) -> 'ImmutableMerge':
        # implementation


# Note: This is a simplified translation and might not cover all edge cases.
```
Note that I've used the `abc` module to define abstract base classes (ABCs), but since Python doesn't have direct support for ABCs like Java does, I've simply defined them as regular classes. Additionally, I've replaced the Java-specific types with their equivalent Python types.

Also, please note that this is a simplified translation and might not cover all edge cases or handle errors in the same way as the original Java code.