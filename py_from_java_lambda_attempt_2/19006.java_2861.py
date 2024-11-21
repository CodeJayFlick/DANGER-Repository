Here is the translation of the given Java interface into a Python class:

```Python
from typing import List, Optional

class CommitLogEntry:
    def __init__(self,
                 created_time: int,
                 hash: str,
                 parents: List[str],
                 metadata: bytes,
                 puts: List[tuple],
                 deletes: List[str],
                 key_list_distance: int,
                 key_list: Optional['KeyList'] = None,
                 key_lists_ids: List[str] = []) -> None:
        self.created_time = created_time
        self.hash = hash
        self.parents = parents
        self.metadata = metadata
        self.puts = puts
        self.deletes = deletes
        self.key_list_distance = key_list_distance
        self.key_list = key_list
        self.key_lists_ids = key_lists_ids

    def get_created_time(self) -> int:
        return self.created_time

    def get_hash(self) -> str:
        return self.hash

    def get_parents(self) -> List[str]:
        return self.parents

    def get_metadata(self) -> bytes:
        return self.metadata

    def get_puts(self) -> List[tuple]:
        return self.puts

    def get_deletes(self) -> List[str]:
        return self.deletes

    def get_key_list_distance(self) -> int:
        return self.key_list_distance

    def get_key_list(self) -> Optional['KeyList']:
        return self.key_list

    @classmethod
    def of(cls,
           created_time: int,
           hash: str,
           parents: List[str],
           metadata: bytes,
           puts: List[tuple],
           deletes: List[str],
           key_list_distance: int,
           key_list: Optional['KeyList'] = None,
           key_lists_ids: List[str] = []) -> 'CommitLogEntry':
        return cls(created_time, hash, parents, metadata, puts, deletes, key_list_distance, key_list, key_lists_ids)
```

Note that I've used Python's type hinting to indicate the types of variables and function parameters.