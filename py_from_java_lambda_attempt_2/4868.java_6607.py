Here is the translation of the Java code to Python:
```
class CFragUsage2Union:
    k_no_app_sub_folder = 0

    def __init__(self, reader):
        self.app_subdir_id = reader.read_short()

    @property
    def application_subdirectory_id(self):
        return self.app_subdir_id

    def to_data_type(self) -> tuple:
        from ghidra_util import StructConverterUtil
        try:
            return StructConverterUtil.to_data_type(type(self))
        except Exception as e:
            raise DuplicateNameException(str(e)) from None
```
Note that I've used the `@property` decorator to create a read-only property for the `application_subdirectory_id`, and also converted the Java-style constructor to Python's `__init__` method. Additionally, I've replaced the `throws IOException` clause with a try-except block in the `to_data_type` method.

Also, please note that this code assumes you have a `reader` object that has a `read_short()` method, and also imports from `ghidra_util`. You may need to adjust these parts based on your specific use case.