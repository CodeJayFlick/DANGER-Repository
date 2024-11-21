class Diff:
    def __init__(self, key: str, from_value=None, to_value=None):
        self.key = key
        self.from_value = from_value
        self.to_value = to_value

    @property
    def get_key(self) -> str:
        return self.key

    @property
    def get_from_value(self) -> Optional['any']:
        return self.from_value

    @property
    def get_to_value(self) -> Optional['any']:
        return self.to_value

def of(key: str, from_value=None, to_value=None):
    return Diff(key, from_value, to_value)
