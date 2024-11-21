Here is the translation of the Java code to Python:
```
class LazyGTestNode:
    def __init__(self, name: str, depth: int):
        self.name = name
        self.depth = depth

    @property
    def name(self) -> str:
        return self._name

    @property
    def get_icon(self, expanded: bool) -> None:
        return None

    @property
    def tooltip(self) -> str:
        return f"tooltip: {self.name}"

    @property
    def is_leaf(self) -> bool:
        return self.depth == 0

    def generate_children(self) -> list['LazyGTestNode']:
        children = []
        if self.depth == 0:
            return children

        for i in range(3):
            child_name = f"{self.name}_{i}"
            children.append(LazyGTestNode(child_name, self.depth - 1))
        return children
```
Note that I've used Python's type hints and properties to mimic the Java code. In particular:

* The `__init__` method is equivalent to the Java constructor.
* The `@property` decorator allows us to define getter methods for attributes like `name`.
* The `f"..."` string formatting syntax is used instead of concatenating strings with `+`.

Also, I've assumed that `GTreeNode` is a Python class (not shown in the original code), and replaced it with a type hint. If you need more help or clarification, feel free to ask!