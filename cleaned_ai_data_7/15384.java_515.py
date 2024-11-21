class Node:
    def __init__(self, data):
        self.data = data
        self.next = None


class LinkedList:
    class Node:
        pass  # This line can be removed if you don't need the inner class in python.

    def __init__(self):
        self.head = None

    def print_list(self):
        current_node = self.head
        while current_node is not None:
            print(current_node.data, end=" ")
            current_node = current_node.next


llist = LinkedList()

node1 = Node(1)
node2 = Node(2)
node3 = Node(3)

llist.head = node1
node1.next = node2
node2.next = node3

print("Linked list: ", end="")
llist.print_list()
