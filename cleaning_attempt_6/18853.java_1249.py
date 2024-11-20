from dataclasses import dataclass, field
import jsonpickle

@dataclass(frozen=True)
class EntriesResponse:
    entries: List['Entry'] = field(default_factory=list)

    @classmethod
    def builder(cls):
        return cls()

def get_entries(self) -> List['Entry']:
    return self.entries


@dataclass(frozen=True)
class Entry:
    type: 'Contents.Type' = None
    name: 'ContentsKey' = None

    @classmethod
    def builder(cls):
        return cls()


def get_type(self) -> 'Contents.Type':
    return self.type


def get_name(self) -> 'ContentsKey':
    return self.name


class Contents:
    class Type(str, Enum):
        pass  # Add your types here

    class Key(str, Enum):
        pass  # Add your keys here
