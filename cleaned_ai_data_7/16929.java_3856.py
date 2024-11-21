import random
from typing import List

class RandomOnDiskUsableSpaceStrategy:
    def __init__(self):
        self.random = random.Random()

    def next_folder_index(self) -> int:
        space_list = self.get_folder_usable_space_list()
        if sum(space_list) <= 0:
            raise DiskSpaceInsufficientException("folders")

        random_value = (self.random.randint(1, max(space_list)) % sum(space_list))
        index = 0
        while index < len(space_list) and random_value >= space_list[index]:
            random_value -= space_list[index]
            index += 1

        return index

    def get_folder_usable_space_list(self) -> List[int]:
        space_list = []
        for folder in self.folders:
            space_list.append(CommonUtils.get_usable_space(folder))
        return space_list


class DiskSpaceInsufficientException(Exception):
    pass
