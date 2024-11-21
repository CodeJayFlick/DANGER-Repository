Here is the translation of the given Java code into Python:

```Python
class CoarseGrainedObject:
    def __init__(self):
        self.dependent_objects = []

    def set_data(self, *data):
        for i in range(len(data)):
            dependent_object = data[i]
            # Assuming DependentObject class has a method setData()
            dependent_object.set_data()

    def get_data(self):
        return [dependent_object.get_data() for dependent_object in self.dependent_objects]

class DependentObject:
    def __init__(self, *data):
        pass

    def set_data(self, data):
        # Assuming this class has a method setData()
        pass
```

Please note that Python does not support generics like Java. The equivalent of `DependentObject<T>` in Python would be defining the type as an argument to the constructor or using duck typing (where you don't specify types but ensure they behave similarly).