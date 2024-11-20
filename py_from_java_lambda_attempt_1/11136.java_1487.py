Here is the translation of the given Java code into Python:

```Python
import io
from typing import List, Any

class ProjectDataNewFolderAction:
    def __init__(self, owner: str, group: str) -> None:
        self.icon = ResourceManager.load_image("images/folder_add.png")
        super().__init__("New Folder", owner)

    @property
    def popup_menu_data(self):
        return MenuData(["New Folder"], self.icon, group)

    def is_add_to_popup(self, context: Any) -> bool:
        return (context.folder_count + context.file_count) == 1

    def action_performed(self, context: Any) -> None:
        self.create_new_folder(context)

    def create_new_folder(self, context: Any) -> None:
        parent_folder = self.get_folder(context)
        new_folder = self.create_new_folder_with_default_name(parent_folder)
        tree = context.tree
        io.run_later(lambda: 
            node = self.find_node_for_folder(tree, new_folder)
            if node is not None:
                tree.set_editable(True)
                tree.start_editing(node.parent, node.name))

    def create_new_folder_with_default_name(self, parent_folder: Any) -> Any:
        name = self.get_new_folder_name(parent_folder)
        try:
            return parent_folder.create_folder(name)
        except (InvalidNameException, io.IOException as e):
            raise AssertionError(f"Unexpected Error creating new folder: {name}", e)

    @staticmethod
    def get_folder_path(folder: Any, folder_path_list: List[str]) -> None:
        if folder.parent is not None:
            ProjectDataNewFolderAction.get_folder_path(folder.parent, folder_path_list)
            folder_path_list.append(folder.name)

    def find_node_for_folder(self, tree: Any, new_folder: Any) -> Any:
        folder_path_list = []
        self.get_folder_path(new_folder, folder_path_list)
        node = tree.model_root
        for i in range(len(folder_path_list)):
            if node is None or not hasattr(node, 'child'):
                return None
            node = getattr(node, 'child')(folder_path_list[i])
        return node

    def get_new_folder_name(self, parent: Any) -> str:
        base_name = "NewFolder"
        name = base_name
        suffix = 1
        while True:
            if not hasattr(parent, f'get_folder({name})'):
                break
            suffix += 1
            name = f"{base_name}{suffix}"
        return name

    def get_folder(self, context: Any) -> Any:
        if context.folder_count > 0:
            return context.selected_folders[0]
        file = context.selected_files[0]
        return file.parent
```

Please note that this is a direct translation of the Java code into Python and may not be optimal or idiomatic for Python.