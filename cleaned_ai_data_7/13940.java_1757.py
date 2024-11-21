class PersistenceTest:
    def __init__(self):
        self.console = ConsoleCoarseGrainedObject()

    def test_dependent_object_changed_for_persistence(self):
        dependent_object = MessageDependentObject()
        self.console.init()
        self.console.dependent_objects[0] = dependent_object
        message = "Danger"
        assert dependent_object.data is None
        dependent_object.set_data(message)
        assert dependent_object.data == message

    def test_coarse_grained_object_changed_for_persistence(self):
        dependent_object = MessageDependentObject()
        self.console.init()
        self.console.dependent_objects[0] = dependent_object
        message = "Danger"
        assert dependent_object.data is None
        self.console.set_data(message)
        assert dependent_object.data == message


class ConsoleCoarseGrainedObject:
    def __init__(self):
        self.dependent_objects = [None]
        self.init()

    def init(self):
        pass

    def set_data(self, data):
        pass


class MessageDependentObject:
    def __init__(self):
        self.data = None

    def set_data(self, data):
        self.data = data
