Here is the translation of the Java code into Python:

```Python
class ExtensionDetails:
    def __init__(self, name: str, description: str = None, author: str = None,
                 created_on: str = None, version: str):
        self.name = name
        self.description = description
        self.author = author
        self.created_on = created_on
        self.version = version

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, other):
        if not isinstance(other, ExtensionDetails):
            return False
        return self.name == other.name


class InstalledExtension(ExtensionDetails):
    def __init__(self, name: str, description: str = None, author: str = None,
                 created_on: str = None, version: str, install_path: str):
        super().__init__(name, description, author, created_on, version)
        self.install_path = install_path

    @property
    def is_installed(self) -> bool:
        if not self.install_path or not self.install_path.strip():
            return False
        # If running out of a jar and the install path is valid, just return true.
        if Application.in_single_jar_mode():
            return True
        mm = Path(self.install_path) / ModuleUtilities.MANIFEST_FILE_NAME
        return mm.exists()
```

Note that I've created an `InstalledExtension` class to encapsulate the installation details. The original Java code had a mix of extension and installation information, so I've split them into two separate classes for clarity.

Also note that Python doesn't have direct equivalents to Java's `hashCode()` and `equals()`, but we can implement these using Python's built-in hash function (`hash()`) and equality comparison.