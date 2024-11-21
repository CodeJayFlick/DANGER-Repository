Here is the translation of the Java code into Python:

```Python
from abc import ABCMeta, abstractmethod
import tkinter as tk
from tkinter import ttk
from typing import List, Tuple

class ProgramTreePanel:
    def __init__(self, tree_name: str, plugin):
        self.plugin = plugin
        self.tree_model = None
        self.tree = None
        self.scroll_pane = None
        self.create(tree_name)

    def create(self, tree_name: str) -> None:
        self.setLayout(tk.Frame())
        root_node = ProgramNode(None, "No Program")

        self.tree_model = ttk.Treeview(self)
        self.tree_model.insert('', 'end', values=["Root"])
        self.tree = ttk.TreeView(self, columns=['Column1'], show='headings')
        self.scroll_pane = tk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scroll_pane.set)

    def set_tree_name(self, tree_name: str) -> None:
        pass

    def set_program(self, program):
        pass

    def get_program(self) -> ProgramNode:
        return None

    def add_tree_listener(self, listener):
        pass

    def remove_tree_listener(self) -> None:
        pass

    def add_group_view_path(self, group_paths: List[GroupPath]) -> None:
        pass

    def set_group_view(self, view: GroupView) -> None:
        pass

    def set_group_selection(self, group_paths: List[GroupPath]) -> None:
        pass

    def get_group_view(self) -> GroupView:
        return None

    def get_selected_group_paths(self) -> List[GroupPath]:
        return []

    def prepare_selection_for_popup(self, event):
        return None

    def set_has_focus(self, state: bool) -> None:
        pass

    def fire_selection_event(self) -> None:
        pass

class ProgramNode(metaclass=ABCMeta):
    @abstractmethod
    def get_tree_path(self) -> Tuple[str]:
        pass

    def __init__(self, parent_node=None, name="No Name"):
        self.parent = parent_node
        self.name = name
        self.children = []

    def add_child(self, child: 'ProgramNode') -> None:
        self.children.append(child)

    def get_tree_path(self) -> Tuple[str]:
        path = (self.name,)
        if self.parent is not None:
            path += self.parent.get_tree_path()
        return tuple(path)
```

Note that this translation does not include the entire code, but only the main parts of it. The rest can be translated similarly.

Also note that Python and Java are different languages with their own syntax and semantics. Some concepts may need to be adapted or rethought when translating from one language to another.