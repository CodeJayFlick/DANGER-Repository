class ByteTrieNode:
    def __init__(self, id: int, parent=None, length=0):
        self.id = id
        self.parent = parent
        self.length = length
        self.children = {}
        self.suffix = None

class SearchResult:
    def __init__(self, node: 'ByteTrieNode', position: int, item):
        self.node = node
        self.position = position
        self.item = item

class ByteTrie(T):
    BUFFER_SIZE = 1 << 20
    GVID = long('-9223372036854775808')

    def __init__(self):
        self.root = self._generate_node(0, None, 0)
        self.version_id = self.get_version_id()
        self.suffix_id = -9223372036854775808
        self.size = 0
        self.number_of_nodes = 1

    @staticmethod
    def get_version_id():
        return ByteTrie.GVID + 1

    def _generate_node(self, id: int, parent=None, length=0):
        return ByteTrieNode(id, parent, length)

    def is_empty(self) -> bool:
        return self.size == 0

    @property
    def size(self) -> int:
        return self._size

    @size.setter
    def size(self, value: int):
        self._size = value

    @property
    def number_of_nodes(self) -> int:
        return self._number_of_nodes

    @number_of_nodes.setter
    def number_of_nodes(self, value: int):
        self._number_of_nodes = value

    def add(self, value: bytes, item: T) -> bool:
        absent = False
        if not value:
            absent = not self.root.is_terminal()
            self.root.set_terminal(None)
            if absent:
                self.size += 1
            return absent
        node = self.root
        offset = 0
        while offset < len(value):
            c = value[offset]
            child_node = node.get_child(c)
            if child_node is None:
                child_node = self._generate_node(c, node, node.length + 1)
                node.add_child(c, child_node)
                self.number_of_nodes += 1
            offset += 1
            node = child_node
        absent = not node.is_terminal()
        node.set_terminal(item)
        if absent:
            self.size += 1
        return absent

    def find(self, value: bytes) -> 'ByteTrieNode':
        if not value:
            return self.root
        offset = 0
        node = self.root
        while offset < len(value):
            c = value[offset]
            child_node = node.get_child(c)
            if child_node is None:
                return None
            offset += 1
            node = child_node
        return node

    def inorder(self, monitor: 'TaskMonitor', op: Op[T]) -> None:
        stack = []
        parent_stack = [None]
        top = self.root
        while top is not None:
            if monitor.check_cancelled():
                break
            monitor.increment_progress(1)
            op(op(top))
            if top.is_terminal():
                results.append(SearchResult(top, 0, top.item))
            top = top.suffix

    def search(self, text: bytes, monitor: 'TaskMonitor') -> List[SearchResult]:
        monitor.initialize(self.number_of_nodes + len(text))
        self._fixup_suffix_pointers(monitor)
        results = []
        node = self.root
        index = 0
        while index < len(text):
            if monitor.check_cancelled():
                break
            monitor.increment_progress(1)
            child_node = None
            while child_node is None:
                child_node = self._get_transition(node, text[index])
                if node == self.root:
                    break
                if child_node is None:
                    node = node.suffix
                else:
                    node = child_node
            if child_node is not None:
                node = child_node
            while node.is_terminal():
                results.append(SearchResult(node, index - node.length + 1, node.item))
                node = node.suffix
            index += 1

        return results

    def _fixup_suffix_pointers(self, monitor: 'TaskMonitor') -> None:
        if self.version_id > self.suffix_id:
            queue = []
            for child in self.root.children.values():
                child.suffix = self.root
                queue.append(child)
            self.root.suffix = self.root
            while queue:
                node = queue.pop(0)
                monitor.check_cancelled()
                monitor.increment_progress(1)
                for child_id, child_node in node.children.items():
                    tmp_child = node
                    id = child_node.id
                    while True:
                        if tmp_child is None or tmp_child.suffix.get_child(id) is None:
                            break
                        queue.append(tmp_child.suffix.get_child(id))
                        tmp_child = tmp_child.suffix
                child_node.suffix = tmp_child.get_child(id)
            self.suffix_id = self.version_id

    def _get_transition(self, node: 'ByteTrieNode', value: int) -> 'ByteTrieNode':
        child_node = node.get_child(value)
        while child_node is None and node != self.root:
            node = node.suffix
            if child_node := node.get_child(value):
                return child_node
        return self.root

class Op(T):
    def __init__(self, op: Callable[[T], None]):
        self.op = op

class TaskMonitor:
    def __init__(self):
        pass

    def initialize(self, progress: int) -> None:
        pass

    def check_cancelled(self) -> bool:
        return False

    def increment_progress(self, value: int) -> None:
        pass
