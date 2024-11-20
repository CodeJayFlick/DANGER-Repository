class SearchResult(P, T):
    def __init__(self, node: 'ByteTrieNode[T]', position: P, item: T) -> None:
        self.node = node
        self.position = position
        self.item = item

    @property
    def node(self) -> 'ByteTrieNode[T]':
        return self._node

    @node.setter
    def node(self, value: 'ByteTrieNode[T]') -> None:
        self._node = value

    @property
    def position(self) -> P:
        return self._position

    @position.setter
    def position(self, value: P) -> None:
        self._position = value

    @property
    def item(self) -> T:
        return self._item

    @item.setter
    def item(self, value: T) -> None:
        self._item = value

    def __str__(self) -> str:
        return f"{self.item}:{self.position}"
