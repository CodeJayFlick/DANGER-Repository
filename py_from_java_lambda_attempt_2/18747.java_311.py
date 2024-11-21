Here is the translation of the Java code to Python:
```
import re

class GetReferenceBuilder:
    def __init__(self):
        pass

    def ref_name(self, ref_name: str) -> 'GetReferenceBuilder':
        if not ref_name or not re.match(Validation.REF_NAME_OR_HASH_REGEX, ref_name):
            raise ValueError(Validation.REF_NAME_OR_HASH_MESSAGE)
        return self

    def get(self) -> Reference:
        # TO DO: implement the logic to retrieve a reference
        pass


class Reference:
    pass


class Validation:
    REF_NAME_OR_HASH_REGEX = r"^[a-zA-Z0-9_\-\.]+$"
    REF_NAME_OR_HASH_MESSAGE = "Invalid reference name or hash"


# Example usage:
builder = GetReferenceBuilder()
reference = builder.ref_name("my-ref").get()  # TO DO: implement the logic to retrieve a reference
```
Note that I've made some assumptions about the Python code, such as:

* The `GetReferenceBuilder` class is an interface in Java, but it's not possible to directly translate interfaces to Python. Instead, I've implemented it as a regular Python class.
* The `Reference` and `Validation` classes are also not interfaces, so they're simply implemented as regular Python classes.
* The `get()` method of the `GetReferenceBuilder` class is currently just a placeholder that returns nothing (i.e., `None`). You'll need to implement the actual logic to retrieve a reference in this method.

I hope this helps! Let me know if you have any further questions.