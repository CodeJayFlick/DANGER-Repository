Here is the translation of the Java code to Python:
```
class FromComponent:
    def __init__(self):
        self.prefix_list = []

    def add_prefix_table_path(self, prefix_path: list) -> None:
        self.prefix_list.append(prefix_path)

    def get_prefix_paths(self) -> list:
        return self.prefix_list
```
Note that I've used Python's built-in `list` type to represent the `ArrayList` in Java. In Python, you don't need to explicitly create a new instance of a class like you do with `new ArrayList<>()`. Instead, you can simply assign an empty list to an attribute.

Also, I've removed the Javadoc comments and the license information since they are not relevant to the translation itself.