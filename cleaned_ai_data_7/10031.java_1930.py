class LazyGTestNode:
    def __init__(self, name: str, depth: int):
        self.name = name
        self.depth = depth

    @property
    def name(self) -> str:
        return self._name

    @property
    def get_icon(self, expanded: bool) -> None:
        return None

    @property
    def tooltip(self) -> str:
        return f"tooltip: {self.name}"

    @property
    def is_leaf(self) -> bool:
        return self.depth == 0

    def generate_children(self) -> list['LazyGTestNode']:
        children = []
        if self.depth == 0:
            return children

        for i in range(3):
            child_name = f"{self.name}_{i}"
            children.append(LazyGTestNode(child_name, self.depth - 1))
        return children
