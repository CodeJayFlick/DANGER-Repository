Here is a translation of the Java code into equivalent Python code:

```Python
# This plugin provides hover text for scalar values in decompiler.
from ghidra_app import CorePluginPackage
from ghidra_framework_plugintool import *

class ScalarValueDecompilerHoverPlugin:
    def __init__(self, tool):
        super().__init__()
        self.scalar_hover_service = ScalarValueDecompilerHover(tool)
        register_service_provided(DecompilerHoverService, self.scalar_hover_service)

# This is the service that provides hover text for scalar values.
class DecompilerHoverService:

    pass

# This class represents a plugin in ghidra
class Plugin:
    def __init__(self):
        super().__init__()

if __name__ == "__main__":
    # Create an instance of your plugin and register it with the tool.
    tool = CorePluginPackage()
    plugin = ScalarValueDecompilerHoverPlugin(tool)
```

Please note that this is a translation, not a direct equivalent. Python does not have exact equivalents for Java classes like `@PluginInfo`, `package` statements or other annotations.