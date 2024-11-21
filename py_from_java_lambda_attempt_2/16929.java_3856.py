Here is the equivalent Python code:

```Python
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
```

Note that Python does not have a direct equivalent to Java's `@Override` annotation. The method is simply declared with the same name and signature as its superclass counterpart.

Also, note that in Python, we don't need to specify types for variables or function parameters like we do in Java.