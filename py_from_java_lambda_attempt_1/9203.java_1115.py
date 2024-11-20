Here is the translation of the Java interface into a Python class:

```Python
class DBFileListener:
    """Facilitates listener notification when new database versions are created."""
    
    def version_created(self, db: str, version: int):
        """A new database version has been created.
        
        Args:
            db (str): The name of the database.
            version (int): The number of the newly created version.
        """
```

Note that Python does not have a direct equivalent to Java's interface concept. Instead, we define a class with methods that can be overridden by subclasses. In this case, I've defined an abstract base class `DBFileListener` with one method `version_created`.