class ReferenceConflictException(Exception):
    def __init__(self, message):
        super().__init__(message)

    @staticmethod
    def for_reference(ref: 'NamedRef', expected_hash: Optional['Hash'], actual_hash: Optional['Hash']) -> 'ReferenceConflictException':
        ref_type = "branch" if isinstance(ref, BranchName) else ("tag" if isinstance(ref, TagName) else "named ref")
        return ReferenceConflictException(f"Expected {expected_hash.map(Hash.as_string).orElse('no reference')} for {ref_type} '{ref.name}' but was {actual_hash.map(Hash.as_string).orElse('no reference')}")


    @staticmethod
    def for_reference(ref: 'NamedRef', expected_hash: Optional['Hash'], actual_hash: Optional['Hash'], exception: Exception) -> 'ReferenceConflictException':
        ref_type = "branch" if isinstance(ref, BranchName) else ("tag" if isinstance(ref, TagName) else "named ref")
        return ReferenceConflictException(f"Expected {expected_hash.map(Hash.as_string).orElse('no reference')} for {ref_type} '{ref.name}' but was {actual_hash.map(Hash.as_string).orElse('no reference')}", exception)
