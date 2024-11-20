class ProjectTreeContext:
    def __init__(self):
        pass

    def get_folder_count(self) -> int:
        raise NotImplementedError("Method not implemented")

    def get_file_count(self) -> int:
        raise NotImplementedError("Method not implemented")

    def get_selected_folders(self) -> list:
        raise NotImplementedError("Method not implemented")

    def get_selected_files(self) -> list:
        raise NotImplementedError("Method not implemented")

    def get_tree(self) -> object:  # DataTree
        raise NotImplementedError("Method not implemented")

    def get_selection_paths(self) -> list:
        raise NotImplementedError("Method not implemented")
