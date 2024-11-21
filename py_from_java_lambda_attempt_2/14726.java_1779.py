Here is the translation of the Java code to Python:

```Python
class StewData:
    def __init__(self, num_potatoes: int, num_carrots: int, num_meat: int, num_peppers: int):
        self.num_potatoes = num_potatoes
        self.num_carrots = num_carrots
        self.num_meat = num_meat
        self.num_peppers = num_peppers

    def get_num_potatoes(self) -> int:
        return self.num_potatoes

    def get_num_carrots(self) -> int:
        return self.num_carrots

    def get_num_meat(self) -> int:
        return self.num_meat

    def get_num_peppers(self) -> int:
        return self.num_peppers
```

Note that Python does not have a direct equivalent to Java's `private` and `final` keywords. In this translation, I've used the convention of prefixing variable names with underscores (`_`) to indicate they are intended to be private (i.e., only accessible within the class).