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
