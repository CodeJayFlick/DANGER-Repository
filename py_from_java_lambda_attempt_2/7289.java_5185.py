Here is the translation of the Java code to Python:
```
class Ext4File:
    def __init__(self, name: str, inode):
        self.name = name
        self.inode = inode

    @property
    def name(self) -> str:
        return self._name

    @property
    def inode(self) -> object:
        return self._inode


# Example usage:
if __name__ == "__main__":
    ext4_file = Ext4File("example.ext4", {"some": "data"})
    print(ext4_file.name)
    print(ext4_file.inode)
```
Note that I used the `@property` decorator to create read-only properties for the `name` and `inode` attributes, similar to how it's done in Java.