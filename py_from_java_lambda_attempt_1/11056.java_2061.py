Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from PIL import ImageTk, Image

class DomainFolderNode:
    ENABLED_OPEN_FOLDER = None
    ENABLED_CLOSED_FOLDER = None
    DISABLED_OPEN_FOLDER = None
    DISABLED_CLOSED_FOLDER = None

    def __init__(self, domain_folder: 'DomainFolder', filter):
        self.domain_folder = domain_folder
        self.filter = filter
        if domain_folder:
            self.tool_tip_text = domain_folder.get_pathname()
            self.is_editable = domain_folder.is_in_writable_project()

    @property
    def domain_folder(self):
        return self._domain_folder

    @domain_folder.setter
    def domain_folder(self, value):
        self._domain_folder = value

    def get_domain_folder(self):
        return self.domain_folder

    def is_leaf(self):
        return False

    def set_is_cut(self, is_cut: bool):
        self.is_cut = is_cut
        # fire_node_changed(get_parent(), this)

    @property
    def is_cut(self):
        return self._is_cut

    @is_cut.setter
    def is_cut(self, value):
        self._is_cut = value

    def get_icon(self, expanded: bool):
        if expanded:
            return self.is_cut and DomainFolderNode.DISABLED_OPEN_FOLDER or DomainFolderNode.ENABLED_OPEN_FOLDER
        else:
            return self.is_cut and DomainFolderNode.DISABLED_CLOSED_FOLDER or DomainFolderNode.ENABLED_CLOSED_FOLDER

    def get_name(self):
        return self.domain_folder.get_name()

    def __str__(self):
        return str(self.get_name())

    @property
    def tool_tip_text(self):
        return self._tool_tip_text

    @tool_tip_text.setter
    def tool_tip_text(self, value):
        self._tool_tip_text = value

    def get_tool_tip(self):
        return self.tool_tip_text

    def generate_children(self) -> list:
        children = []
        if self.domain_folder:
            folders = self.domain_folder.get_folders()
            for folder in folders:
                children.append(DomainFolderNode(folder, self.filter))
            files = self.domain_folder.get_files()
            for file in files:
                if not self.filter or self.filter.accept(file):
                    children.append(DomainFileNode(file))
        return sorted(children)

    @property
    def is_editable(self):
        return self._is_editable

    @is_editable.setter
    def is_editable(self, value):
        self._is_editable = value

    def is_editable_(self) -> bool:
        return self.is_editable

    def equals(self, obj: object) -> bool:
        if not isinstance(obj, DomainFolderNode):
            return False
        if self.domain_folder == obj.domain_folder:
            return True
        return False

    def __hash__(self) -> int:
        return hash(self.domain_folder)

    @property
    def domain_file_filter(self):
        return self._domain_file_filter

    @domain_file_filter.setter
    def domain_file_filter(self, value):
        self._domain_file_filter = value

    def get_domain_file_filter(self):
        return self.domain_file_filter

    def compare_to(self, node: 'GTreeNode') -> int:
        if isinstance(node, DomainFileNode):
            return -1
        else:
            return super().compare_to(node)

    def value_changed(self, new_value: object) -> None:
        if str(new_value) == self.get_name():
            return

        try:
            self.domain_folder.set_name(str(new_value))
        except InvalidNameException as e:
            tk.messagebox.showerror("Rename Failed", "Invalid name: " + str(new_value), parent=self)
        except IOException as e:
            tk.messagebox.showerror("Rename Failed", e.get_message(), parent=self)

class DomainFileNode(GTreeLazyNode):
    pass
```

Note that I have not implemented the `GTreeNode` class and its methods (`generateChildren`, etc.) in Python, because they seem to be specific to Java's Swing framework.