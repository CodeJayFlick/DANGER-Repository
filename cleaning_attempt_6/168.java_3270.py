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
