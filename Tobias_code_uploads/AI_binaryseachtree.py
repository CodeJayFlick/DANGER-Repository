class Node:
    def __init__(self, key):
        self.left = None
        self.right = None
        self.value = key

class BinarySearchTree:
    def __init__(self):
        self.root = None

    # Insert a node into the BST
    def insert(self, key):
        if self.root is None:
            self.root = Node(key)
        else:
            self._insert(self.root, key)

    def _insert(self, current_node, key):
        if key < current_node.value:
            if current_node.left is None:
                current_node.left = Node(key)
            else:
                self._insert(current_node.left, key)
        elif key > current_node.value:
            if current_node.right is None:
                current_node.right = Node(key)
            else:
                self._insert(current_node.right, key)
        else:
            print(f"Node with value {key} already exists in the BST.")

    # Search for a node in the BST
    def search(self, key):
        return self._search(self.root, key)

    def _search(self, current_node, key):
        if current_node is None:
            return False
        if current_node.value == key:
            return True
        elif key < current_node.value:
            return self._search(current_node.left, key)
        else:
            return self._search(current_node.right, key)

    # In-order traversal (left, root, right)
    def inorder(self):
        return self._inorder(self.root, [])

    def _inorder(self, current_node, result):
        if current_node:
            self._inorder(current_node.left, result)
            result.append(current_node.value)
            self._inorder(current_node.right, result)
        return result

    # Pre-order traversal (root, left, right)
    def preorder(self):
        return self._preorder(self.root, [])

    def _preorder(self, current_node, result):
        if current_node:
            result.append(current_node.value)
            self._preorder(current_node.left, result)
            self._preorder(current_node.right, result)
        return result

    # Post-order traversal (left, right, root)
    def postorder(self):
        return self._postorder(self.root, [])

    def _postorder(self, current_node, result):
        if current_node:
            self._postorder(current_node.left, result)
            self._postorder(current_node.right, result)
            result.append(current_node.value)
        return result

# Example usage:
bst = BinarySearchTree()

# Inserting multiple values
values = [50, 30, 70, 20, 40, 60, 80, 25, 35, 65, 75]
print(f"Inserting values: {values}")
for value in values:
    bst.insert(value)

# Traversal outputs
print("\nIn-order Traversal:", bst.inorder())
print("Pre-order Traversal:", bst.preorder())
print("Post-order Traversal:", bst.postorder())

# Searching for nodes
search_values = [40, 100, 25, 85]
print("\nSearching for values:", search_values)
for val in search_values:
    found = bst.search(val)
    print(f"Value {val} found in BST: {found}")

# Trying to insert duplicate values
duplicate_values = [50, 35, 70]
print("\nInserting duplicate values:", duplicate_values)
for value in duplicate_values:
    bst.insert(value)

# Re-running traversals after attempting duplicate inserts
print("\nIn-order Traversal after duplicate insertions:", bst.inorder())
