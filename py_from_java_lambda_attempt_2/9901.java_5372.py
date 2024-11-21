Here is the translation of the Java interface `GTreeTextFilterFactory` to a Python class:
```python
class GTreeTextFilterFactory:
    def __init__(self):
        pass

    def get_tree_filter(self, filter_text: str, transformer) -> object:
        # Note: In Python, we don't have generics like in Java,
        # so I'll just return an object for now. You can modify
        # this method to create a suitable filtering mechanism.
        return None  # Replace with your implementation

    def set_filter_options(self, options):
        pass  # Implement me!

    def get_filter_options(self) -> object:
        return None  # Replace with your implementation
```
Note that I've kept the method signatures similar to the original Java interface. However, since Python is dynamically typed and doesn't have generics like Java does, some of these methods will need to be modified or replaced depending on how you choose to implement them.

Also, keep in mind that this translation assumes a basic understanding of object-oriented programming concepts between Java and Python. If there are specific requirements or constraints for your project, please let me know!