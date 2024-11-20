Here is the translation of the Java code to Python:
```
class StorageGroupAlreadySetException(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)

    @classmethod
    def from_path(cls, path: str, has_child: bool = False) -> 'StorageGroupAlreadySetException':
        if not has_child:
            message = f"{path} has already been set to storage group"
        else:
            message = f"Some children of {path} have already been set to storage group"
        return cls(message)

    @property
    def path(self) -> str:
        return self.args[0]

    @property
    def has_child(self) -> bool:
        return len(self.args) > 1 and self.args[1]
```
Note that I've used Python's built-in `Exception` class as the base class for our custom exception, since there is no direct equivalent to Java's `MetadataException`. The rest of the code translates fairly straightforwardly.