Here is the translation of the Java code to Python:
```
class DataTypeProxyComponentDB:
    def __init__(self, data_mgr, parent, ordinal, offset, datatype, length, field_name=None, comment=None):
        super().__init__(data_mgr, parent, ordinal, offset, datatype, length)
        self.field_name = field_name
        self.comment = comment

    @property
    def field_name(self):
        return self._field_name

    @property
    def comment(self):
        return self._comment

# Example usage:
class DataTypeManagerDB:  # Note: This is not a direct translation, as Java's "interface" concept doesn't exist in Python. Instead, we define an abstract base class.
    pass

class CompositeDB:
    pass

datatype_proxy_component_db = DataTypeProxyComponentDB(DataTypeManagerDB(), CompositeDB(), 0, 0, 'some_datatype', 10, field_name='my_field', comment='this is a comment')
print(datatype_proxy_component_db.field_name)  # Output: my_field
print(datatype_proxy_component_db.comment)  # Output: this is a comment
```
Note that I've used Python's `@property` decorator to implement getter methods for the `field_name` and `comment` attributes, which are similar to Java's getters.