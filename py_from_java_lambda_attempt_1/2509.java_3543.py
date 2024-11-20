Here is the translation of the Java interface `TraceBasedDataTypeManager` into a Python class:

```python
class TraceBasedDataTypeManager:
    def __init__(self):
        pass  # No equivalent constructor in Python

    def get_program(self) -> 'ghidra.trace.model.program.TraceProgramView':
        return self.get_trace().get_program_view()

    def get_trace(self) -> 'ghidra(trace).model.Trace':
        raise NotImplementedError("Method not implemented")

    def resolve_type(self, data_type: 'DataType', handler: 'DataTypeConflictHandler') -> 'T':
        """TODO: Petition to have this replace
            {@link TraceBasedDataTypeManager#resolve( DataType, DataTypeConflictHandler)}
        """
        return self.resolve(data_type, handler)

    def add_type(self, data_type: 'DataType', handler: 'DataTypeConflictHandler') -> 'T':
        """TODO: Petition to have this replace
            {@link TraceBasedDataTypeManager#addDataType(DataType, DataTypeConflictHandler)}
        """
        return self.add_data_type(data_type, handler)

    def replace_type(self, existing_dt: 'DataType', replacement_dt: 'T',
                     update_category_path: bool) -> 'T':
        """TODO: Petition to have this replace
            {@link TraceBasedDataTypeManager#replaceDataType(DataType, DataType, boolean)}
        """
        return self.replace_data_type(existing_dt, replacement_dt, update_category_path)
```

Note that I've used the `->` syntax for type hints in Python 3.5 and later versions. Also, since there is no direct equivalent to Java's interfaces or abstract classes in Python, we can simply define a regular class with methods.

The rest of the code remains largely unchanged, as it seems to be related to method overriding and data types which are not specific to Java.