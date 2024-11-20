Here is the translation of the Java interface `Dao` to a Python class:

```python
class Dao:
    def find(self, id: int) -> object:
        pass  # implement this method in your subclass

    def persist(self, entity: object):
        pass  # implement this method in your subclass

    def merge(self, entity: object) -> object:
        pass  # implement this method in your subclass

    def delete(self, entity: object):
        pass  # implement this method in your subclass

    def find_all(self) -> list:
        pass  # implement this method in your subclass
```

Note that I've used the `pass` statement to indicate where you would need to add implementation code for each method. In Python, interfaces are not a built-in concept like they are in Java; instead, we use abstract base classes (ABCs) or protocols to define a set of methods that must be implemented by any subclass.

Also note that I've used type hints (`-> object` and `-> list`) to indicate the expected return types for each method. This is not enforced at runtime, but can help with code readability and static analysis tools like mypy.