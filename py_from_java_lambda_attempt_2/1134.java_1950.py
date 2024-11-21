Here is the translation of the given Java code into equivalent Python:

```Python
from enum import Enum

class VTIndices(Enum):
    NOTIFY_SCRIPT_CHANGE = 0
    GET_NAMESPACE_OBJECT = 1


class IDataModelScriptHostContext:
    IID_IDATA_MODEL_SCRIPT_HOST_CONTEXT = "014D366A-1F23-4981-9219-B2DB8B402054"

    def __init__(self):
        pass

    def notify_script_change(self, script: int, change_kind: int) -> None:
        # Implement the logic for NotifyScriptChange
        pass

    def get_namespace_object(self) -> int:
        # Implement the logic for GetNamespaceObject
        return 0


# Usage example:

host = IDataModelScriptHostContext()
script = 1
change_kind = 2
result = host.notify_script_change(script, change_kind)
print(result)

namespace_obj_ref = PointerByReference(0)  # Initialize with some default value
result = host.get_namespace_object(namespace_obj_ref)
print(result)
```

Please note that the translation is not a direct equivalent of Java code. Python has different syntax and structure than Java.