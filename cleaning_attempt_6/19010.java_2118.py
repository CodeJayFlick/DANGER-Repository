from enum import Enum

class ContentsType(Enum):
    pass  # You need to define your contents types here


class ContentsIdWithType:
    def __init__(self, contents_id: str, type: ContentsType):
        self.contents_id = contents_id
        self.type = type

    @classmethod
    def of(cls, contents_id: str, type: ContentsType) -> 'ContentsIdWithType':
        return cls(contents_id=contents_id, type=type)
