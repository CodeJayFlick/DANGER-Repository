from typing import List, Set

class PathPattern:
    def __init__(self, pattern: List[str]):
        self.pattern = list(pattern)

    def __str__(self):
        return f"<PathPattern {PathUtils.to_string(self.pattern)}>"

    def __eq__(self, other):
        if not isinstance(other, PathPattern):
            return False
        return self.pattern == other.pattern

    def __hash__(self):
        return hash(self.pattern)

    @staticmethod
    def is_wildcard(pat: str) -> bool:
        return pat in ["[]", ""]

    @classmethod
    def key_matches(cls, pat: str, key: str) -> bool:
        if pat == key:
            return True
        if cls.is_wildcard(pat) and PathUtils.is_index(key):
            return True
        if "" == pat and PathUtils.is_name(key):
            return True
        return False

    def matches_up_to(self, path: List[str], length: int) -> bool:
        for i in range(length):
            if not self.key_matches(self.pattern[i], path[i]):
                return False
        return True

    def matches(self, path: List[str]) -> bool:
        if len(path) != len(self.pattern):
            return False
        return self.matches_up_to(path, len(path))

    def successor_could_match(self, path: List[str], strict: bool) -> bool:
        if len(path) > len(self.pattern):
            return False
        if strict and len(path) == len(self.pattern):
            return False
        return self.matches_upto(path, len(path))

    def ancestor_matches(self, path: List[str], strict: bool) -> bool:
        if len(path) < len(self.pattern):
            return False
        if strict and len(path) == len(self.pattern):
            return False
        return self.matches_up_to(path, len(self.pattern))

    @staticmethod
    def contains_wildcards(pattern: List[str]) -> bool:
        for pat in pattern:
            if PathPattern.is_wildcard(pat):
                return True
        return False

    def get_singleton_path(self) -> List[str]:
        if self.contains_wildcards(self.pattern):
            return None
        return list(self.pattern)

    def count_wildcards(self) -> int:
        return sum(1 for k in self.pattern if PathPattern.is_wildcard(k))

    def get_singleton_pattern(self) -> 'PathPattern':
        return self

    def next_names(self, path: List[str]) -> Set[str]:
        if len(path) >= len(self.pattern):
            return set()
        pat = self.pattern[path.index]
        if PathUtils.is_name(pat):
            return {pat}
        return set()

    def next_indices(self, path: List[str]) -> Set[int | str]:
        if len(path) >= len(self.pattern):
            return set()
        pat = self.pattern[path.index]
        if PathUtils.is_index(pat):
            return {PathUtils.parse_index(pat)}
        return set()

    def is_empty(self) -> bool:
        return False

    def apply_indices(self, indices: List[str]) -> 'PathPattern':
        result = []
        for i, pat in enumerate(self.pattern):
            if self.contains_wildcard(pat):
                index = next((i for i in indices), None)
                if PathUtils.is_index(pat):
                    result.append(PathUtils.make_key(index))
                else:
                    result.append(index)
            else:
                result.append(pat)
        return PathPattern(result)

    def match_indices(self, path: List[str]) -> List[str | int]:
        length = len(self.pattern)
        if length != len(path):
            return None
        result = []
        for i in range(length):
            pat = self.pattern[i]
            key = path[i]
            if not PathPattern.key_matches(pat, key):
                return None
            if PathPattern.is_wildcard(pat):
                if PathUtils.is_index(pat):
                    result.append(PathUtils.parse_index(key))
                else:
                    result.append(key)
        return result

class PathUtils:
    @staticmethod
    def is_name(s: str) -> bool:
        # implement this method as needed
        pass

    @staticmethod
    def is_index(s: str) -> bool:
        # implement this method as needed
        pass

    @staticmethod
    def parse_index(s: str) -> int | str:
        # implement this method as needed
        pass

    @staticmethod
    def make_key(index: int | str) -> str:
        return f"[{index}]"

    @staticmethod
    def to_string(pattern: List[str]) -> str:
        return ", ".join(map(str, pattern))
