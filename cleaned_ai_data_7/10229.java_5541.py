class ListNodeSTL:
    def __init__(self, prev=None, node=None, value=None):
        self.prev = prev
        self.next = node
        self.value = value


class ListSTL:
    def __init__(self):
        self.root = None
        self.size = 0

    @property
    def EOL(self):
        return '\n'

    def __str__(self):
        buffy = "ListSTL[size=" + str(self.size) + "]"
        current = self.root.next if self.root else None
        for i in range(min(20, self.size)):
            buffy += "\t[" + str(i) + "]=" + str(current.value) + self.EOL
            current = current.next
        return buffy

    def printDebug(self):
        begin = self.begin()
        while not begin.is_end():
            t = begin.get()
            begin.increment()
            value = "null" if t is None else str(t)
            print(value, end=self.EOL)
        print()

    def begin(self):
        return ListIteratorSTL(self, self.root.next)

    def end(self):
        return ListIteratorSTL(self, self.root)

    def rBegin(self):
        return ReverseListIteratorSTL(self, self.root.prev)

    def rEnd(self):
        return ReverseListIteratorSTL(self, self.root)

    @property
    def size(self):
        return self._size

    @size.setter
    def size(self, value):
        self._size = value

    def clear(self):
        self.size = 0
        self.root = None

    def isEmpty(self):
        return self.size == 0

    def front(self):
        if self.isEmpty():
            raise IndexError()
        return self.root.next.value

    def back(self):
        if self.isEmpty():
            raise IndexError()
        return self.root.prev.value

    def push_back(self, value):
        new_node = ListNodeSTL(prev=self.root.prev, node=self.root, value=value)
        self.root.prev.next = new_node
        self.root.prev = new_node
        self.size += 1

    def push_front(self, value):
        new_node = ListNodeSTL(prev=self.root, node=self.root.next, value=value)
        self.root.next.prev = new_node
        self.root.next = new_node
        self.size += 1

    def insert(self, position, value):
        new_node = ListNodeSTL(prev=self.root.prev, node=self.root, value=value)
        list_iterator = ListIteratorSTL(position.list, position.node)
        new_node.next = list_iterator.node
        new_node.prev = list_iterator.node.prev
        new_node.prev.next = new_node
        new_node.next.prev = new_node
        self.size += 1
        return ListIteratorSTL(self, self.root, new_node)

    def erase(self, position):
        if not isinstance(position.list, ListSTL) or position.list is not self:
            raise RuntimeError("Attempting to erase using an iterator from a different list")
        node = position.node

        node.prev.next = node.next
        node.next.prev = node.prev
        self.size -= 1

    def pop_front(self):
        if self.isEmpty():
            raise IndexError()
        node = self.root.next
        node.next.prev = self.root
        self.root.next = node.next
        node.next = None
        node.prev = None
        self.size -= 1
        return node.value

    def pop_back(self):
        if self.isEmpty():
            raise IndexError()
        node = self.root.prev
        node.prev.next = self.root
        self.root.prev = node.prev
        node.next = None
        node.prev = None
        self.size -= 1
        return node.value

    def adjustSize(self, count):
        self.size += count

    def equals(self, obj):
        if obj is None:
            return False
        if obj == this:
            return True
        if not isinstance(obj, ListSTL):
            return False
        other = obj
        if self.size != other.size:
            return False
        it1 = self.begin()
        it2 = other.begin()
        while not it1.is_end():
            value1 = it1.get()
            value2 = it2.get()
            if value1 is None and value2 is not None or value1 is not None and value2 is None:
                return False
            if value1 != value2:
                return False
            it1.increment()
            it2.increment()
        return True

    def sort(self, comparator):
        TERMINAL = ListNodeSTL(prev=None)
        if self.size <= 1:
            return
        self.root.prev.next = TERMINAL
        node = mergeSort(self.root.next, comparator, TERMINAL)
        prev_node = self.root
        while node is not TERMINAL:
            node.prev = prev_node
            prev_node = node
            node = node.next
        prev_node.next = self.root
        self.root.prev = prev_node

    @staticmethod
    def mergeSort(a, comparator, TERMINAL):
        if a.next is TERMINAL or (a is not TERMINAL and comparator.compare(a.value, a.next.value) <= 0):
            return a
        b = a.next.next
        while b is not TERMINAL:
            a = a.next
            b = b.next
        b = a.next
        return merge(mergeSort(a, comparator, TERMINAL), mergeSort(b, comparator, TERMINAL), comparator, TERMINAL)

    @staticmethod
    def merge(a, b, comparator, TERMINAL):
        head = ListNodeSTL(prev=None)
        c = head
        while True:
            if b is TERMINAL or (a is not TERMINAL and comparator.compare(a.value, b.value) <= 0):
                c.next = a
                a = a.next
            else:
                c.next = b
                b = b.next
            if a is TERMINAL and b is TERMINAL:
                break
        return head.next

    def splice(self, position, list2, it3):
        to_position = ListIteratorSTL(position.list, position.node)
        from_position = ListIteratorSTL(list2, it3.node)
        node = from_position.node
        node.prev.next = node.next
        node.next.prev = node.prev
        list2.size -= 1

        node.next = it3.node
        node.prev = it3.node.prev
        it3.node.prev.next = node
        it3.node.next.prev = node
        self.size += 1


class ListIteratorSTL:
    def __init__(self, list_, node_):
        self.list = list_
        self.node = node_

    @property
    def is_end(self):
        return self.node is None

    def get(self):
        if not self.is_end():
            value = self.node.value
            self.increment()
            return value
        raise IndexError()

    def increment(self):
        if not self.is_end():
            self.node = self.node.next


class ReverseListIteratorSTL:
    def __init__(self, list_, node_):
        self.list = list_
        self.node = node_

    @property
    def is_end(self):
        return self.node is None

    def get(self):
        if not self.is_end():
            value = self.node.value
            self.increment()
            return value
        raise IndexError()

    def increment(self):
        if not self.is_end():
            self.node = self.node.prev


# test code
list_ = ListSTL()
list_.push_back(5)
list_.push_back(10)
list_.push_back(3)
list_.push_back(7)
list_.push_back(6)

print("   ONE")
it1 = list_.begin()
while not it1.is_end():
    print("value =", it1.getAndIncrement())

print("   TWO")
list_.sort()

it2 = list_.begin()
while not it2.is_end():
    print("value =", it2.getAndIncrement())

print("  THREE")

it3 = list_.rBegin()
while not it3.is_end():
    print("value =", it3.getAndIncrement())

list_2 = ListSTL()
list_2.push_back(1000)
list_2.push_back(1001)
list_2.push_back(1002)
list_2.push_back(1003)
list_2.push_back(1004)

it5 = list_2.begin()
it5.increment()
it5.increment()

print("pre-splice list")
it6 = list_2.begin()
while not it6.is_end():
    print("value =", it6.getAndIncrement())

list_.splice(list_.end(), list_2, it3)

print("repaired list")
it7 = list_2.begin()
while not it7.is_end():
    print("value =", it7.getAndIncrement())
