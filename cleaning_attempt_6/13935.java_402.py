class ConsoleCoarseGrainedObject:
    def __init__(self):
        self.dependent_objects = [MessageDependentObject(), SignalDependentObject()]

    def get_data(self) -> list[str]:
        return [
            dependent_object.get_data() for dependent_object in self.dependent_objects
        ]

# Helper classes
class DependentObject:
    pass

class MessageDependentObject(DependentObject):
    def get_data(self) -> str:
        # Implement your logic here to generate data for this object.
        return "Message Data"

class SignalDependentObject(DependentObject):
    def get_data(self) -> str:
        # Implement your logic here to generate data for this object.
        return "Signal Data"
