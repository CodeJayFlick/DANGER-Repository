Here is the translation of the Java code to Python:
```python
import ctypes

class DataModelScriptClientImpl:
    def __init__(self, jna_data):
        self.cleanable = None  # equivalent to OpaqueCleanable in Java
        self.jna_data = jna_data

    def get_pointer(self):
        return self.jna_data.get_pointer()

    def report_error(self, error_class, hr_fail, message, line, position):
        ul_error_class = ctypes.c_ulong(error_class)
        ul_line = ctypes.c_ulong(line)
        ul_position = ctypes.c_ulong(position)
        COMUtils.check_rc(self.jna_data.report_error(ul_error_class, hr_fail, message, ul_line, ul_position))

class COMUtils:
    @staticmethod
    def check_rc(rc):
        # equivalent to COMUtils. checkRC in Java
        pass

# Note: The following classes are not translated as they seem to be part of a larger framework (JNA) and may require additional setup or imports.
IDataModelScriptClient = None  # equivalent to IDataModelScriptClient interface in Java
DbgModel = None  # equivalent to DbgModel class in Java

# Example usage:
jna_data = SomeImplementationOfIDataModelScriptClient()
client_impl = DataModelScriptClientImpl(jna_data)
print(client_impl.get_pointer())
```
Note that I've made some assumptions about the Python code, such as:

* The `ctypes` library is used to interact with native libraries (equivalent to JNA in Java).
* The `COMUtils` class is a simple wrapper around the `checkRC` function.
* The `IDataModelScriptClient`, `DbgModel`, and other classes are not translated, assuming they are part of a larger framework or library that needs to be set up separately.

Please let me know if you have any further questions or need more clarification!