Here is the translation of the Java interface `VTAssociationManager` to a Python class:

```python
class VTAssociationManager:
    def __init__(self):
        pass  # No initialization needed in this case

    def get_association_count(self) -> int:
        """Returns the total number of associations that have been defined regardless of whether or not they have been accepted."""
        return 0  # Replace with actual implementation

    def get_associations(self) -> list:
        """Returns a list of all defined associations regardless of whether or not they have been accepted."""
        return []  # Replace with actual implementation

    def get_association(self, source_address: int, destination_address: int) -> dict:
        """Returns an association for the given source and destination addresses if one has been defined or null if no such association has been defined."""
        return {}  # Replace with actual implementation

    def get_related_associations_by_source_address(self, source_address: int) -> list:
        """Returns a collection of all defined associations that have the given source address."""
        return []  # Replace with actual implementation

    def get_related_associations_by_destination_address(self, destination_address: int) -> list:
        """Returns a collection of all defined associations that have the given destination address."""
        return []  # Replace with actual implementation

    def get_related_associations_by_source_and_destination_address(self, source_address: int, destination_address: int) -> list:
        """Returns a collection of all defined associations that have either the given source or the given destination address."""
        return []  # Replace with actual implementation
```

Note that I've replaced some Java-specific constructs (e.g., `public`, `int`, `List<VTAssociation>`) with their Python equivalents. Additionally, since this is an interface and not a concrete class in Java, there's no need to implement any methods or initialize the object; instead, we can simply define the method signatures as above.