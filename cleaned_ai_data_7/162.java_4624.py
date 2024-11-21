import tkinter as tk
from tkinter import ttk
from typing import List, Dict, Any

class ObjectTree:
    def __init__(self, container: 'ObjectContainer'):
        self.root = None  # type: ObjectNode
        self.tree = None  # type: GTree
        self.current_selection_paths = []  # type: list[ttk.TreePath]
        self.current_expanded_paths = []  # type: list[tuple[Any, ...]]
        self.current_view_position = None  # type: tuple[int, int]

        self.node_map = {}  # type: Dict[str, ObjectNode]
        self.restore_tree_state_manager = tk.Toplevel()  # type: Toplevel

        self.listing_service = container.get_provider().get_listing_service()
        self.model_service = container.get_provider().get_model_service()

    def get_container(self) -> 'ObjectContainer':
        return self.root.container if self.root else None

    def get_target_object(self) -> Any:
        return self.root.target_object if self.root else None

    def get_provider(self) -> 'DebuggerObjectsProvider':
        return self.root.provider if self.root else None

    # ... (rest of the methods)

class ObjectNode:
    def __init__(self, tree: 'ObjectTree', parent_container: Any, container: 'ObjectContainer'):
        self.tree = tree
        self.parent_container = parent_container
        self.container = container
        self.target_object = container.get_target_object()
        self.provider = container.get_provider()

    # ... (rest of the methods)

class GTree(ttk.TreeView):
    def __init__(self, root: 'ObjectNode'):
        super().__init__()
        self.root = root

    # ... (rest of the methods)
