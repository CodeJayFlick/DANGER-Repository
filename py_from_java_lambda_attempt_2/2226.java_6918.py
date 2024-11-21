Here is the translation of the Java interface `PathPredicates` into a Python class:

```Python
from typing import List, Set, Dict, Any, Callable, Optional

class PathPredicates:
    def matches(self, path: List[str]) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def successor_could_match(self, path: List[str], strict: bool) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def ancestor_matches(self, path: List[str], strict: bool) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def get_next_names(self, path: List[str]) -> Set[str]:
        raise NotImplementedError("Subclasses must implement this method")

    def get_next_indices(self, path: List[str]) -> Set[str]:
        raise NotImplementedError("Subclasses must implement this method")

    def get_singleton_path(self) -> Optional[List[str]]:
        return None

    def get_singleton_pattern(self) -> Any:
        return None

    @staticmethod
    def any_matches(pats: Set[str], key: str) -> bool:
        for pat in pats:
            if not pat:
                return True
            if key == pat:
                return True
        return False

    def get_cached_values(self, path: List[str], seed: Any) -> Dict[List[str], Any]:
        raise NotImplementedError("Subclasses must implement this method")

    def get_cached_successors(self, path: List[str], cur: Any) -> Dict[List[str], Any]:
        raise NotImplementedError("Subclasses must implement this method")

    async def fetch_successors(self, seed: Any) -> Optional[Dict[List[str], Any]]:
        return None

    def apply_indices(self, indices: List[str]) -> 'PathPredicates':
        raise NotImplementedError("Subclasses must implement this method")
```

Note that the `get_cached_values`, `get_cached_successors`, and `fetch_successors` methods are asynchronous in Python (using the `async/await` syntax), whereas they were not in Java.