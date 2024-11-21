Here is the translation of the Java code to Python:

```Python
import array
from typing import List

class DragDropTreeTransferable:
    local_tree_node_flavor = create_local_tree_node_flavor()

    def __init__(self, nodes: list):
        self.data_list = array.array('L', [node.id for node in nodes])

    @staticmethod
    def create_local_tree_node_flavor():
        return "application/x-java-jVMLocalObject; class=list"

    flavors = [local_tree_node_flavor]

    flavor_list = array.array('O', [flavors[0]])

    def get_transfer_data_flavors(self):
        return self.flavors

    def is_data_flavor_supported(self, f: str) -> bool:
        return f in self.flavor_list.tolist()

    def get_transfer_data(self, f: str) -> object:
        if f == self.local_tree_node_flavor:
            return self.data_list
        else:
            raise Exception("Unsupported flavor")

    def __str__(self):
        return "DragDropTreeTransferable"

# Note that the lostOwnership method is not implemented in Python as it's a part of Java's ClipboardOwner interface.
```

Please note that this translation does not include all parts of the original code, especially those related to clipboard operations.