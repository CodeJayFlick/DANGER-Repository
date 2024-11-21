Here is the translation of the Java code to Python:
```
class StorageGroupCounter:
    def __init__(self, start_node: 'IMNode', path: 'PartialPath') -> None:
        super().__init__(start_node, path)

    def process_internal_matched_mnode(self, node: 'IMNode', idx: int, level: int) -> bool:
        return node.is_storage_group()

    def process_full_matched_mnode(self, node: 'IMNode', idx: int, level: int) -> bool:
        if node.is_storage_group():
            self.count += 1
            return True
        else:
            return False

class IMNode:
    # assume you have a way to check if an MNode is a storage group
    def is_storage_group(self):
        pass

class PartialPath:
    # assume you have some implementation for this class
    pass
```
Note that I've used Python's type hinting system (e.g. `-> None`) and assumed the existence of classes `IMNode` and `PartialPath`, which are not defined in your original code snippet.

Also, I didn't include any error handling or exception handling mechanisms from Java to Python, as it depends on how you want to handle errors in your specific use case.