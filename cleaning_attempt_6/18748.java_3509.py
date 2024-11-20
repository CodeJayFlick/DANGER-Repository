class MergeReferenceBuilder:
    def __init__(self):
        pass

    def from_hash(self, from_hash: str) -> 'MergeReferenceBuilder':
        if not from_hash:
            raise ValueError("fromHash cannot be blank")
        return self

    def from_ref_name(self, from_ref_name: str) -> 'MergeReferenceBuilder':
        import re
        pattern = re.compile(Validation.REF_NAME_REGEX)
        if not pattern.match(from_ref_name):
            raise ValueError(f"Invalid ref name {from_ref_name}")
        return self

    @property
    def from_ref(self):
        pass  # This is a property, we don't need to implement it here.

    def merge(self) -> None:
        raise NessieNotFoundException("Not found")
        raise NessieConflictException("Conflict")

class Reference:
    def __init__(self, name: str, hash: str):
        self.name = name
        self.hash = hash

    @property
    def get_name(self) -> str:
        return self.name

    @property
    def get_hash(self) -> str:
        return self.hash


class Validation:
    REF_NAME_REGEX = r"^[a-zA-Z0-9_\-\.]+$"
    REF_NAME_MESSAGE = "Invalid ref name"


if __name__ == "__main__":
    mrb = MergeReferenceBuilder()
    reference = Reference("ref_name", "hash")
    mrb.from_ref(from_ref=reference).merge()

