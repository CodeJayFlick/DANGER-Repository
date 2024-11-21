Here is the equivalent Python code:

```Python
class DirectoryListModel:
    def __init__(self):
        self.file_list = []

    def get_element_at(self, index):
        return self.file_list[index]

    def set_file(self, index, file):
        old_file = self.file_list.pop(index)
        self.fire_contents_changed(0, len(self.file_list) - 1)
        self.file_list.insert(index, file)

    def contains(self, file):
        return file in self.file_list

    def insert(self, file):
        self.file_list.append(file)
        self.fire_interval_added(len(self.file_list) - 1, len(self.file_list) - 1)

    def set_files(self, new_file_list):
        size = len(self.file_list)
        self.file_list.clear()
        self.fire_interval_removed(0, size)
        if new_file_list:
            self.file_list.extend(new_file_list)
            self.fire_interval_added(0, len(self.file_list) - 1)

    def get_file(self, index):
        return self.file_list[index] if 0 <= index < len(self.file_list) else None

    def update(self):
        self.fire_contents_changed(0, len(self.file_list) - 1)

    def find_index_of_file(self, file):
        try:
            return self.file_list.index(file)
        except ValueError:
            return -1

    def get_all_files(self):
        return list(self.file_list[:])

    def fire_contents_changed(self, start, end):
        # implement this method
        pass

    def fire_interval_added(self, index0, index1):
        # implement this method
        pass

    def fire_interval_removed(self, index0, index1):
        # implement this method
        pass

    def get_size(self):
        return len(self.file_list)
```

Note that the `fire_contents_changed`, `fire_interval_added` and `fire_interval_removed` methods are placeholders in Python. In Java, these methods were used to notify listeners of changes made to the list model. You would need to implement similar functionality in your Python code if you want to use this class with a GUI framework like Tkinter or PyQt that supports notification of data changes.