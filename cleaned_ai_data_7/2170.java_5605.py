import typing as t

TargetElementType = t.NamedTuple('TargetElementType', [
    ('index', str),
    ('type', type)
])

class TargetElementType:
    def __init__(self, index: str = "", type: type = type):
        self.index = index
        self.type = type
