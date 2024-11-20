Here is the translation of the Java code to Python:
```
class ObjectUpdatedEvent:
    def __init__(self, object_container):
        self.object = object_container

    @property
    def object(self):
        return self._object

    def __str__(self):
        return f"ObjectUpdatedEvent({self.object.name}, 'update')"

import ghidra_framework_plugintool_plugin_event as PluginEvent  # assuming this is the equivalent Python module

class ObjectContainer:
    pass  # placeholder, you'll need to define this class in your actual code
```
Note that I've used a property (`@property`) to expose the `object` attribute, and defined an `__str__` method to provide a string representation of the event. The rest of the translation is straightforward.

Also, please note that I'm assuming you have a Python module called `ghidra_framework_plugintool_plugin_event.py` which contains the equivalent functionality for the Java class `PluginEvent`. You'll need to define this module in your actual code.