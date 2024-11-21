import pickle

class ComponentTransferableData:
    def __init__(self, dock_comp):
        info = dock_comp.get_component_windowing_placeholder()
        self.owner = info.get_owner()
        self.name = info.get_name()

# Note: In Python, we don't need a separate class for serialization like Java's Serializable interface.
