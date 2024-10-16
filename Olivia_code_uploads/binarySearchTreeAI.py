class TreeNode:
    def __init__(self, value):
        self.value = value
        self.left = None
        self.right = None

class BinarySearchTree:
    def __init__(self):
        self.root = None

    # Insert a new node with the specified value
    def insert(self, value):
        if not self.root:
            self.root = TreeNode(value)
        else:
            self._insert_recursive(self.root, value)
    
    # Helper method for recursive insertion
    def _insert_recursive(self, node, value):
        if value < node.value:
            if not node.left:
                node.left = TreeNode(value)
            else:
                self._insert_recursive(node.left, value)
        else:
            if not node.right:
                node.right = TreeNode(value)
            else:
                self._insert_recursive(node.right)
    
    # Search for a node with the specified value
    def search(self, value):
        return self._search_recursive(self.root, value)
    
    # Helper method for recursive search
    def _search_recursive(self, node, value):
        if not node or node.value == value:
            return node
        if value < node.value:
            return self._search_recursive(node.left, value)
        return self._search_recursive(node.right)
    
    # In-order traversal to print the BST
    def in_order_traversal(self):
        self._in_order_recursive(self.root)
        print()  # for a new line after traversal
    
    # Helper method for recursive in-order traversal
    def _in_order_recursive(self, node):
        if node:
            self._in_order_recursive(node.left)
            print(node.value, end=' ')
            self._in_order_recursive(node.right)

# Example usage:
# Create a binary search tree and insert values into it
bst = BinarySearchTree()
values = [66, 45, 35, 71, 65, 62, 59]
for value in values:
    bst.insert(value)

# Print the tree in in-order traversal
print("In-order traversal of the BST:")
bst.in_order_traversal()

# Search for a value in the BST
search_value = 65
found_node = bst.search(search_value)
if found_node:
    print(f"Value {search_value} found in the tree.")
else:
    print(f"Value {search_value} not found in the tree.")