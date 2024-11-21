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
