import logging

class MinFolderOccupiedSpaceFirstStrategy:
    def __init__(self):
        self.folders = []

    def next_folder_index(self) -> int:
        return self.get_min_occupied_space_folder()

    def get_min_occupied_space_folder(self) -> int:
        min_index = -1
        min_space = float('inf')

        for i, folder in enumerate(self.folders):
            if not has_space(folder):
                continue

            try:
                space = get_occupied_space(folder)
            except Exception as e:
                logging.error(f"Cannot calculate occupied space for path {folder}: {e}")
            if space < min_space:
                min_space = space
                min_index = i

        if min_index == -1:
            raise DiskSpaceInsufficientException(self.folders)

        return min_index


def has_space(folder):
    # implement this function to check if a folder has available space
    pass


def get_occupied_space(folder):
    # implement this function to calculate the occupied space of a folder
    pass


class DiskSpaceInsufficientException(Exception):
    def __init__(self, folders):
        super().__init__(f"Disk space insufficient for folders: {folders}")
