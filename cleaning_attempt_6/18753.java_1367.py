import re

class OnTagBuilder:
    def __init__(self):
        pass

    def tag_name(self, tag_name: str) -> 'OnTagBuilder':
        if not isinstance(tag_name, str):
            raise ValueError("tag name must be a string")
        pattern = re.compile(Validation.REF_NAME_REGEX)
        if not pattern.match(tag_name):
            raise ValueError(f"Invalid tag name: {tag_name}")
        return self

    def hash(self, hash_value: str) -> 'OnTagBuilder':
        if not isinstance(hash_value, str):
            raise ValueError("hash value must be a string")
        pattern = re.compile(Validation.HASH_REGEX)
        if not pattern.match(hash_value):
            raise ValueError(f"Invalid hash value: {hash_value}")
        return self

    def tag(self, tag: dict) -> 'OnTagBuilder':
        """Convenience method for setting both tag name and hash"""
        return self.tag_name(tag['name']).hash(tag['hash'])
