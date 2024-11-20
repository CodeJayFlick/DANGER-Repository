Here is the translation of the given Java code into equivalent Python:

```Python
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
```

Note: Python does not have a direct equivalent to Java's `@Nonnull` annotation. Instead, you can use type hints and the `isinstance()` function to ensure that certain variables are not null or None.

Also note that in Python, we don't need to specify types for method parameters like we do in Java. The `Optional` class is also not directly equivalent to anything in Python; instead, you would typically just check if a value is `None`.