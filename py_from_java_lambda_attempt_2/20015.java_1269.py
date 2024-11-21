Here's your Java interface translated into Python:

```Python
class ClassResolver:
    def __init__(self):
        pass

    @staticmethod
    def get_class(id: str) -> type or None:
        """Resolves a class by its ID."""
        # Your implementation here
        return None  # Replace with actual logic

    @staticmethod
    def get_id(c: type) -> str or None:
        """Gets an ID for a Class. The ID is used to identify the type of a saved object."""
        # Your implementation here
        return None  # Replace with actual logic
```

Note that Python does not have direct equivalents to Java's `@Nullable` and `public`, so I've omitted those annotations in this translation.