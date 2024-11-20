Here is the translation of the Java code to Python:
```
class EntityCounter:
    def __init__(self, start_node: 'IMNode', path: 'PartialPath') -> None:
        super().__init__(start_node, path)

    def process_internal_matched_mnode(self, node: 'IMNode', idx: int, level: int) -> bool:
        return False

    def process_full_matched_mnode(self, node: 'IMNode', idx: int, level: int) -> bool:
        if node.is_entity():
            self.count += 1
        return False
```
Note that I used type hints for the method parameters and variables to indicate their types. This is not strictly necessary in Python, but it can be helpful for code readability and maintainability.

Also, note that I did not include any imports or licenses at the top of the file, as these are typically included separately from the actual code implementation.