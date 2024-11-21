Here is the translation of the given Java code into Python:

```Python
class RecreateSimpleObjects:
    def __init__(self):
        self.names = ["Foo", "Bar", "Baz", "Frodo", "Froyo", "Fizz", "Bip", "Bop", "Bang", "Boo"]
        self.simple_objects = []

    @property
    def number(self):
        return getattr(self, '_number', 3)

    @number.setter
    def number(self, value):
        self._number = value

    @property
    def simple_objects(self):
        return self.__simple_objects

    @simple_objects.setter
    def simple_objects(self, value):
        self.__simple_objects = value

    def execute(self, ec):
        param_number = 3 if not hasattr(ec, 'param') else getattr(ec, 'param', 3)
        
        if param_number < 0 or param_number > len(self.names):
            raise ValueError(f"number must be in range [0,{len(self.names)})")

        SimpleObjectsTearDown().execute_child(self, ec)

        for i in range(param_number):
            fs = SimpleObjectCreate()
            fs.name = self.names[i]
            SimpleObjectsTearDown().execute_child(self, f"{fs.name}", fs)
            self.simple_objects.append(fs.get_simple_object())
```

Please note that Python does not have direct equivalent of Java's List and ArrayList. It uses built-in list type which is dynamic in nature i.e., it can grow or shrink at runtime based on the items added to/from it.