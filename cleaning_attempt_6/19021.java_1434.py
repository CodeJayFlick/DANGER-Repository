class KeyWithType:
    def __init__(self, key: 'Key', contents_id: str, type: int):
        self.key = key
        self.contents_id = contents_id
        self.type = type

    @property
    def get_key(self) -> 'Key':
        return self.key

    @property
    def get_contents_id(self) -> str:
        return self.contents_id

    @property
    def get_type(self) -> int:
        return self.type

def of(key: 'Key', contents_id: str, type: int):
    return KeyWithType(key, contents_id, type)
