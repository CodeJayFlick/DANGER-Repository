Here is the translation of the given Java code into Python:

```Python
import logging

class App:
    TREASURE_CHEST = {"RING": ["Ring1", "Ring2"], 
                       "POTION": ["Potion1", "Potion2"], 
                       "WEAPON": ["Sword1", "Sword2"], 
                       "ANY": []}

    def demonstrate_treasure_chest_iterator(self, item_type):
        logging.info("---------------")
        logging.info(f"Item Iterator for ItemType {item_type}: ")
        for item in self.TREASURE_CHEST.get(item_type, []):
            logging.info(item)

    def build_integer_bst(self):
        root = TreeNode(8)
        
        root.insert(3)
        root.insert(10)
        root.insert(1)
        root.insert(6)
        root.insert(14)
        root.insert(4)
        root.insert(7)
        root.insert(13)

        return root

    def demonstrate_bst_iterator(self):
        logging.info("---------------")
        logging.info("BST Iterator: ")
        
        root = self.build_integer_bst()
        bst_iterator = BstIterator(root)
        
        while bst_iterator.has_next():
            logging.info(f"Next node: {bst_iterator.next().get_val()}")

    def main(self, args):
        for item_type in ["RING", "POTION", "WEAPON", "ANY"]:
            self.demonstrate_treasure_chest_iterator(item_type)
        
        self.demonstrate_bst_iterator()


class TreeNode:
    def __init__(self, val):
        self.val = val
        self.left = None
        self.right = None

    def insert(self, val):
        if val < self.val:
            if not self.left:
                self.left = TreeNode(val)
            else:
                left_node = self.left
                while True:
                    if left_node.val > val:
                        if not left_node.left:
                            left_node.left = TreeNode(val)
                            break
                        left_node = left_node.left
                    elif left_node.val < val:
                        if not left_node.right:
                            left_node.right = TreeNode(val)
                            break
                        left_node = left_node.right
        else:
            if not self.right:
                self.right = TreeNode(val)
            else:
                right_node = self.right
                while True:
                    if right_node.val > val:
                        if not right_node.left:
                            right_node.left = TreeNode(val)
                            break
                        right_node = right_node.left
                    elif right_node.val < val:
                        if not right_node.right:
                            right_node.right = TreeNode(val)
                            break
                        right_node = right_node.right


class BstIterator:
    def __init__(self, root):
        self.root = root

    def has_next(self):
        return self._has_next(self.root)

    def _has_next(self, node):
        if not node:
            return False
        return True

    def next(self):
        current_node = self.root
        while True:
            if not current_node.left and not current_node.right:
                return TreeNode(current_node.val)
            elif not current_node.left:
                return TreeNode(current_node.val)
            else:
                current_node = current_node.left


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    app = App()
    app.main([])
```

This Python code is a direct translation of the given Java code.