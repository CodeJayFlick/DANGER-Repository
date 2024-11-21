import re
from pathlib import Path

class RegexFileFilter:
    def __init__(self):
        self.allow_hidden = False
        self.only_directory = False
        self.pattern = None

    def set_pattern(self, pattern, flags=0):
        if isinstance(pattern, str):
            self.pattern = re.compile(pattern, flags)
        elif isinstance(pattern, re.Pattern):
            self.pattern = pattern

    def accept(self, path: Path) -> bool:
        if not self.allow_hidden and path.name.startswith('.'):
            return False
        if self.only_directory and not path.is_dir():
            return False
        if self.pattern is None or (path.is_dir() and self.pattern.match('') is None):
            return True
        name = str(path)
        match = self.pattern.fullmatch(name)
        return bool(match)

# Example usage:
filter = RegexFileFilter()
filter.set_pattern(r'.*\.txt$')
print(filter.accept(Path('/path/to/file.txt')))  # Returns: True
