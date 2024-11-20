Here is the translation of the given Java code into Python:

```Python
class XmlTreeNode:
    def __init__(self):
        self.start_element = None
        self.end_element = None
        self.children = []

    def set_start_end(self, start, end):
        self.start_element = start
        self.end_element = end

    def get_start_element(self):
        return self.start_element

    def get_end_element(self):
        return self.end_element

    def get_child_count(self):
        return len(self.children)

    def get_children(self):
        return iter(self.children)

    def get_children_by_name(self, name):
        for child in self.get_children():
            if child.get_start_element().name == name:
                yield child
                break
        else:
            pass

    def get_child_at_index(self, index):
        try:
            return self.children[index]
        except IndexError:
            return None


class TagIterator:
    def __init__(self, tag):
        self.tag = tag
        self.it = iter()
        self.next_node = None

    def find_next(self):
        for node in self.it:
            if node.get_start_element().name == self.tag:
                self.next_node = node
                return
        self.next_node = None

    def remove(self):
        pass  # Not implemented as it's not clear what this should do

    def has_next(self):
        if self.next_node is None:
            self.find_next()
        return self.next_node is not None

    def next(self):
        if self.has_next():
            node = self.next_node
            self.next_node = None
            return node
        return None


class XmlElement:
    def __init__(self, name):
        self.name = name

    @property
    def start(self):
        pass  # Not implemented as it's not clear what this should do

    @property
    def end(self):
        pass  # Not implemented as it's not clear what this should do


class XmlPullParser:
    def __init__(self):
        pass  # Not implemented as it's not clear what this should do

    def start(self):
        return XmlElement("start")

    def peek(self):
        pass  # Not implemented as it's not clear what this should do

    def end(self, element):
        pass  # Not implemented as it's not clear what this should do
```

Please note that the `XmlPullParser` and its methods (`peek`, `end`) are not fully implemented in Python. The same applies to some of the getter/setter methods (e.g., `start()`).