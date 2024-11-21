Here is the translation of the Java code to Python:
```
import pickle

class ComponentTransferableData:
    def __init__(self, dock_comp):
        info = dock_comp.get_component_windowing_placeholder()
        self.owner = info.get_owner()
        self.name = info.get_name()

# Note: In Python, we don't need a separate class for serialization like Java's Serializable interface.
```
Note that I used the `pickle` module to achieve similar functionality to Java's `Serializable` interface. Also, in Python, we typically use constructors (`__init__`) instead of explicit constructor methods.

Here is an example usage:
```
class DockableComponent:
    def get_component_windowing_placeholder(self):
        # return some placeholder object
        pass

dock_comp = DockableComponent()
data = ComponentTransferableData(dock_comp)
print(data.owner)  # prints the owner string
print(data.name)   # prints the name string
```
Keep in mind that this is just one possible translation, and you may need to adjust it depending on your specific use case.