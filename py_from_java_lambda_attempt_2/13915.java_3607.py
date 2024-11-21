Here is the translation of the given Java code into Python:

```Python
class Queue:
    def __init__(self):
        self.front = None
        self.rear = None
        self.size = 0

    class Node:
        def __init__(self, value, next=None):
            self.value = value
            self.next = next

    def is_empty(self):
        return self.size == 0

    def enqueue(self, obj):
        if not self.front:
            self.front = self.rear = Queue.Node(obj)
        else:
            new_node = Queue.Node(obj)
            self.rear.next = new_node
            self.rear = new_node
        self.size += 1

    def dequeue(self):
        if self.is_empty():
            raise IsEmptyException()
        temp = self.front
        self.front = self.front.next
        self.size -= 1
        return temp.value

    def peek(self):
        if self.is_empty():
            raise IsEmptyException()
        return self.front.value


class IsEmptyException(Exception):
    pass
```

Please note that Python does not have a direct equivalent to Java's generics. However, you can achieve similar functionality using type hints and the ` typing` module in Python 3.5+.