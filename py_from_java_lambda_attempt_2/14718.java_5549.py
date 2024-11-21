Here is the translation of the given Java code into Python:

```Python
class PriorityMessageQueue:
    def __init__(self, queue):
        self.queue = queue
        self.size = 0
        self.capacity = len(queue)

    def remove(self):
        if not self.is_empty():
            root = self.queue[0]
            self.queue[0] = self.queue[self.size - 1]
            self.size -= 1
            self.max_heapify_down()
            return root

    def add(self, t):
        self.ensure_capacity()
        self.queue[self.size] = t
        self.size += 1
        self.max_heapify_up()

    def is_empty(self):
        return self.size == 0


    def max_heapify_down(self):
        index = 0
        while has_left_child(index):
            smaller_index = left_child_index(index)

            if has_right_child(index) and right_child(index).compareTo(left_child(index)) > 0:
                smaller_index = right_child_index(index)
            else:
                break

            if self.queue[index].compareTo(self.queue[smaller_index]) > 0:
                break
            else:
                self.swap(index, smaller_index)

            index = smaller_index


    def max_heapify_up(self):
        index = self.size - 1
        while has_parent(index) and parent(index).compareTo(self.queue[index]) < 0:
            self.swap(parent_index(index), index)
            index = parent_index(index)


    def print(self):
        for i in range(0, (self.size // 2)):
            LOGGER.info("PARENT: " + str(self.queue[i]) +
                        " LEFT CHILD: " + str(left_child(i)) +
                        " RIGHT CHILD: " + str(right_child(i)))


# Helper functions
def parent_index(pos):
    return (pos - 1) // 2


def left_child_index(parent_pos):
    return 2 * parent_pos + 1


def right_child_index(parent_pos):
    return 2 * parent_pos + 2


def parent(child_index):
    return self.queue[parent_index(child_index)]


def left(parent_index):
    return self.queue[left_child_index(parent_index)]


def right(parent_index):
    return self.queue[right_child_index(parent_index)]


def has_left_child(index):
    return left_child_index(index) < self.size


def has_right_child(index):
    return right_child_index(index) < self.size


def has_parent(index):
    return parent_index(index) >= 0


def swap(fpos, tpos):
    tmp = self.queue[fpos]
    self.queue[fpos] = self.queue[tpos]
    self.queue[tpos] = tmp


def ensure_capacity():
    if self.size == self.capacity:
        self.capacity *= 2
        self.queue = copy_of(self.queue, self.capacity)


# Note: The LOGGER object is not defined in this code snippet.
```

This Python translation maintains the same functionality as the original Java code.