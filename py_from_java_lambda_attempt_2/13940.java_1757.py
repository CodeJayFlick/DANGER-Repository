Here is the equivalent Python code:

```Python
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
```

Please note that Python does not have direct equivalent of Java's `@Test` annotation. Instead, you would typically use a testing framework like unittest or pytest to write test cases.

Also, the `ConsoleCoarseGrainedObject` and `MessageDependentObject` classes are quite abstract in this code snippet, so I've left their methods as pass for simplicity. You might need to implement them based on your actual requirements.