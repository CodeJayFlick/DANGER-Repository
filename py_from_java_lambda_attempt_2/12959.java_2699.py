Here is the translation of the Java code to Python:
```
class TestAddress:
    SPACE = {"name": "TEST", "size": 32, "start": 0, "end": 0}

    def __init__(self, offset):
        super().__init__(offset, self.SPACE)

    def __init__(self, offset, addr_space):
        super().__init__(offset, addr_space)
```
Note that I've used the `super()` function to call the parent class's constructor (`GenericAddress` in this case), and also defined a dictionary for the `SPACE` attribute.