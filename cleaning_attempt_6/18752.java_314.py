class OnReferenceBuilder:
    def __init__(self):
        pass

    def ref_name(self, ref_name: str) -> 'OnReferenceBuilder':
        if not self._validate_ref_name(ref_name):
            raise ValueError("Invalid reference name")
        return self

    def hash_on_ref(self, hash_on_ref: str = None) -> 'OnReferenceBuilder':
        if hash_on_ref is not None and not self._validate_hash(hash_on_ref):
            raise ValueError("Invalid hash value")
        return self

    @property
    def reference(self) -> 'OnReferenceBuilder':
        pass  # To be implemented


def _validate_ref_name(ref_name: str) -> bool:
    import re
    pattern = re.compile(Validation.REF_NAME_REGEX)
    if not pattern.match(ref_name):
        return False
    return True

def _validate_hash(hash_on_ref: str) -> bool:
    import re
    pattern = re.compile(Validation.HASH_REGEX)
    if hash_on_ref is None or not pattern.match(hash_on_ref):
        return False
    return True


class Reference:
    def __init__(self, name: str, hash_value: str):
        self.name = name
        self.hash_value = hash_value

# You need to define Validation class and its properties (REF_NAME_REGEX, REF_NAME_MESSAGE, HASH_REGEX, HASH_MESSAGE)
