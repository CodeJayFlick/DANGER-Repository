import os
from tkinter import *
from tkinter.filedialog import askdirectory
from tkinter.messagebox import showinfo

class NewTestApp:
    def __init__(self):
        pass

    @staticmethod
    def main():
        try:
            root = Tk()
            root.title("Test App")
            root.geometry('400x600')
            root.resizable(False, False)
            frame = Frame(root, bg='gray', highlightthickness=0)
            frame.pack(fill=BOTH, expand=True)

            container = Frame(frame, bg='gray', highlightthickness=0)
            container.pack(fill=BOTH, expand=True)

            tree = GTree(container)
            root.bind('<Button-3>', lambda event: self.right_click(event, tree))

            button = Button(root, text="Push Me", command=lambda: self.push_me(tree))
            button.pack(side=BOTTOM)

        except Exception as e:
            showinfo("Error", str(e))

    @staticmethod
    def right_click(event, tree):
        try:
            selection_path = tree.selection()
            if selection_path:
                node = GTreeNode(selection_path[-1])
                tree.collapse_all(node)
        except Exception as e:
            showinfo("Error", str(e))

    @staticmethod
    def push_me(tree):
        try:
            selection_path = tree.selection()
            if selection_path:
                node = GTreeNode(selection_path[-1])
                tree.collapse_all(node)
        except Exception as e:
            showinfo("Error", str(e))


class FileData:
    def __init__(self, file):
        self.file = file

    @property
    def get_file(self):
        return self.file


class FileNode(GTreeNode, FileData):
    def __init__(self, file):
        super().__init__()
        self.file = file

    @property
    def get_file(self):
        return self.file

    def get_icon(self, expanded=False):
        pass  # You need to implement this method.

    def get_name(self):
        if hasattr(self, 'tempName'):
            return self.tempName
        name = os.path.basename(self.file.name)
        if len(name) > 0:
            return name
        return os.path.basename(self.file.name)

    @property
    def get_tooltip(self):
        return str(self.file.absolute_path)


class DirectoryNode(GTreeLazyNode, FileData):
    def __init__(self, file):
        super().__init__()
        self.file = file

    @property
    def is_leaf(self):
        return False

    def generate_children(self):
        children = []
        for directory_file in os.listdir(str(self.file)):
            if os.path.isdir(os.path.join(str(self.file), directory_file)):
                children.append(DirectoryNode(file=os.path.join(str(self.file), directory_file)))
            else:
                children.append(FileNode(file=os.path.join(str(self.file), directory_file)))

        return sorted(children)

    @property
    def get_tooltip(self):
        return str(self.file.absolute_path)


class RootNode(DirectoryNode, FileData):
    def __init__(self, file):
        super().__init__(file)


class DragNDropHandler:
    supported_flavors = [DataFlavor.stringFlavor, DataFlavor.javaFileListFlavor]

    @staticmethod
    def drop(dest_user_data, transferable, drop_action):
        try:
            list_ = transferable.get_transfer_data(DataFlavor.javaFileListFlavor)
            iterator = iter(list_)
            while iterator:
                print("\t" + next(iterator))
        except (UnsupportedFlavorException, IOException) as e:
            pass

    @staticmethod
    def get_supported_data_flavors(drag_user_data):
        return DragNDropHandler.supported_flavors

    @staticmethod
    def get_supported_drag_actions():
        return DnDConstants.ACTION_COPY


class GTree:
    def __init__(self, container):
        self.container = container
        self.treeview = Treeview(container)
        self.treeview.pack(fill=BOTH, expand=True)

    def set_drag_ndrop_handler(self, handler):
        pass  # You need to implement this method.

    @property
    def get_selection_path(self):
        return self.treeview.selection()

    def collapse_all(self, node):
        pass  # You need to implement this method.


class GTreeNode:
    def __init__(self, file):
        super().__init__()
        self.file = file

    @property
    def is_leaf(self):
        return True


if __name__ == "__main__":
    NewTestApp.main()
