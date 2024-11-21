Here is the translation of the Java code to Python:
```
class EmptyDataSet:
    def __init__(self):
        super().__init__([], [])

    def hasNext_without_constraint(self) -> bool:
        return False

    def next_without_constraint(self) -> object:
        return None
```
Note that I used the `super()` function to call the parent class's constructor, and also used type hints for the method return types. Additionally, in Python, we don't need to specify a package name or import statements like Java does.