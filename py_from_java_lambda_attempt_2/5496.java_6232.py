Here is the translation of the Java interface `ListingField` into a Python class:

```python
class ListingField:
    def __init__(self):
        pass

    def get_field_factory(self) -> object:
        """Returns the FieldFactory that generated this Field"""
        raise NotImplementedError("Method not implemented")

    def get_height_above(self) -> int:
        """Returns the height above the imaginary base line used for alignment of fields"""
        raise NotImplementedError("Method not implemented")

    def get_height_below(self) -> int:
        """Returns the height below the imaginary base line used for alignment of fields"""
        raise NotImplementedError("Method not implemented")

    def get_field_model(self) -> object:
        """Returns the fieldModel that has the FieldFactory that generated this field"""
        raise NotImplementedError("Method not implemented")

    def get_proxy(self) -> object:
        """Returns the object that the fieldFactory used to generate the information in this field"""
        raise NotImplementedError("Method not implemented")

    def get_clicked_object(self, field_location: 'FieldLocation') -> object:
        """Returns the object that was clicked on a Field for the given FieldLocation. This may be the
           field itself or a lower-level entity, such as a FieldElement.
        
           @param field_location The location that was clicked.
           @return the object that was clicked"""
        raise NotImplementedError("Method not implemented")
```

Note: I used Python's `raise` statement to indicate which methods are abstract and should be implemented in any subclass.