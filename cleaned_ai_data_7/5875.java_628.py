from abc import ABC, abstractmethod

class ByteTrieNodeIfc:
    @abstractmethod
    def __init__(self):
        pass

class Trie(ABC):
    @abstractmethod
    def isEmpty(self) -> bool:
        pass

    @abstractmethod
    def size(self) -> int:
        pass

    @abstractmethod
    def number_of_nodes(self) -> int:
        pass

    @abstractmethod
    def add(self, value: bytes, item) -> bool:
        pass

    @abstractmethod
    def find(self, value: bytes) -> 'ByteTrieNodeIfc':
        pass

    @abstractmethod
    def inorder(self, monitor, op):
        pass

    @abstractmethod
    def search(self, text: bytes, monitor) -> list:
        pass

    @abstractmethod
    def search_memory(self, memory, view, monitor) -> list:
        pass


class SearchResult:
    def __init__(self, offset_position, found_text):
        self.offset_position = offset_position
        self.found_text = found_text
