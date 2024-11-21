Here is the translation of the given Java interface into a Python class:

```Python
class TransplantCommitsBuilder:
    def __init__(self):
        pass

    def message(self, message: str) -> 'TransplantCommitsBuilder':
        return self

    def from_ref_name(self, ref_name: str) -> 'TransplantCommitsBuilder':
        if not re.match(Validation.REF_NAME_REGEX, ref_name):
            raise ValueError(Validation.REF_NAME_MESSAGE)
        return self

    def hashes_to_transplant(self, hashes_to_transplant: List[str]) -> None:
        if len(hashes_to_transplant) < 1:
            raise ValueError("List of hashes must not be empty")
        for hash in hashes_to_transplant:
            if not isinstance(hash, str):
                raise TypeError("All elements in the list must be strings")

    def transplant(self) -> None:
        # Your NessieNotFoundException and NessieConflictException logic here
        pass

class Validation:
    REF_NAME_REGEX = r"your regex pattern"
    REF_NAME_MESSAGE = "Invalid ref name"

if __name__ == "__main__":
    builder = TransplantCommitsBuilder()
    try:
        builder.message("Your message").from_ref_name("your-ref-name").hashes_to_transplant(["hash1", "hash2"]).transplant()
    except ValueError as e:
        print(f"Error: {e}")
```

Please note that Python does not have direct equivalent of Java's `@Pattern`, `@NotNull` and `@Size`. These are annotations used for validation. In the above code, I've implemented these validations manually using regular expressions and list length checks.

Also, NessieNotFoundException and NessieConflictException classes were removed as they seem to be specific exceptions in your project. You can replace them with Python's built-in exceptions or implement custom ones if needed.