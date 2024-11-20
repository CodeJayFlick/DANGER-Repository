Here is the translation of the Java code to Python:
```
class FunctionRowObjectToAddressTableRowMapper:
    def map(self, row_object: 'VTFunctionRowObject', data: 'Program', service_provider: 'ServiceProvider') -> Address:
        function_manager = data.get_function_manager()
        info = row_object.get_info()
        function = function_manager.get_function(info.get_function_id())
        return function.get_entry_point()

class VTFunctionRowObject:
    def get_info(self) -> 'FunctionAssociationInfo':
        pass

class FunctionAssociationInfo:
    def get_function_id(self) -> int:
        pass
```
Note that I've kept the type hints in Python, as they are useful for documentation and static analysis. However, if you want to remove them, simply delete the `: '...'` parts.

Also note that this translation is not a direct equivalent of the Java code, but rather an approximation using Python's syntax and semantics. The original Java code may have additional functionality or nuances that are not preserved in this translation.