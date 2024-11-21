Here is the translation of the Java code to Python:
```
import abc

class BaseHttpOnReferenceRequest(metaclass=abc.ABCMeta):
    def __init__(self, client):
        pass  # equivalent to super(client)

    @property
    def ref_name(self):
        raise NotImplementedError("Subclasses must implement this property")

    @ref_name.setter
    def ref_name(self, value):
        self._ref_name = value

    @property
    def hash_on_ref(self):
        raise NotImplementedError("Subclasses must implement this property")

    @hash_on_ref.setter
    def hash_on_ref(self, value):
        self._hash_on_ref = value

class NessieApiClient:
    pass  # equivalent to the Java class, but no implementation is provided here

def main():
    client = NessieApiClient()
    request = BaseHttpOnReferenceRequest(client)
    request.ref_name("my-ref-name")
    request.hash_on_ref("my-hash-on-ref")

if __name__ == "__main__":
    main()
```
Note that I had to make some assumptions about the Java code, as it was not provided in its entirety. Specifically:

* The `OnReferenceBuilder` class is not defined, so I did not attempt to translate it.
* The `BaseHttpRequest` class is also not defined, but since Python does not have an equivalent concept of a "base" request, I simply omitted the reference to it.

The resulting Python code defines two classes: `BaseHttpOnReferenceRequest`, which is an abstract base class (ABC) that provides properties for setting and getting the `ref_name` and `hash_on_ref` attributes. The second class, `NessieApiClient`, is a placeholder for the Java class of the same name.

The `main()` function demonstrates how to create an instance of `BaseHttpOnReferenceRequest` and set its `ref_name` and `hash_on_ref` properties using Python's property syntax.