import logging

class ContentsApiImpl:
    def __init__(self, config: dict, store: dict, access_checker: callable, principal: str):
        pass  # equivalent to super().__init__()

    def get_contents(self, key: tuple, named_ref: str, hash_on_ref: str) -> Optional[dict]:
        ref = self.named_ref_with_hash_or_throw(named_ref, hash_on_ref)
        try:
            obj = store.get(ref.hash, self.to_key(key))
            if obj is not None:
                return obj
            raise NessieContentsNotFoundException(key, named_ref)
        except ReferenceNotFoundException as e:
            raise NessieReferenceNotFoundException(e.message, e)

    def get_multiple_contents(self, named_ref: str, hash_on_ref: str, request: dict) -> Optional[dict]:
        try:
            ref = self.named_ref_with_hash_or_throw(named_ref, hash_on_ref)
            external_keys = [key for key in request['requested_keys']]
            internal_keys = [self.to_key(key) for key in external_keys]
            values = store.get_values(ref.hash, internal_keys)
            output = []

            for i, value in enumerate(values):
                if value is not None:
                    output.append({'key': external_keys[i], 'value': value})

            return {'contents': output}
        except ReferenceNotFoundException as e:
            raise NessieReferenceNotFoundException(e.message, e)

    @staticmethod
    def to_key(key: tuple) -> dict:
        return {'elements': list(key)}

class NessieContentsNotFoundException(Exception):
    pass

class NessieReferenceNotFoundException(Exception):
    pass
