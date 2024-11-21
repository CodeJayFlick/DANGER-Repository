Here is the translation of the Java code to Python:

```Python
class MemviewService:
    def __init__(self):
        pass

    def set_boxes(self, box_list: list) -> None:
        # implement this method in your subclass
        pass

    def init_views(self) -> None:
        # implement this method in your subclass
        pass

    def set_program(self, current_program: object) -> None:
        # implement this method in your subclass
        self.current_program = current_program

    def get_provider(self) -> object:
        # implement this method in your subclass
        return None  # or any other default value you want to return
```

Note that Python does not have direct equivalents for Java's `@ServiceInfo` and `public interface`, so I've translated them into a regular class definition. The methods are also defined as instance methods, since there is no equivalent concept in Python like the "default provider" specified in the original code.

In order to use this class, you would need to create a subclass that implements each of these methods according to your specific needs.