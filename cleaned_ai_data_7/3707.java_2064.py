import threading
from typing import List, Dict

class DataTypeIndexer:
    def __init__(self):
        self.data_type_managers = []
        self.data_types_list = []
        self.data_type_comparator = None
        self.is_stale = True
        self.listener = DataTypeIndexUpdateListener()

    def add_data_type_manager(self, data_type_manager: 'DataTypeManager'):
        if not self.data_type_managers.__contains__(data_type_manager):
            data_type_manager.add_data_type_manager_listener(self.listener)
            data_type_manager.add_invalidated_listener(self.listener)
            self.data_type_managers.append(data_type_manager)
            self.mark_stale()

    def remove_data_type_manager(self, data_type_manager: 'DataTypeManager'):
        if self.data_type_managers.__contains__(data_type_manager):
            data_type_manager.remove_data_type_manager_listener(self.listener)
            data_type_manager.remove_invalidated_listener(self.listener)
            self.data_type_managers.remove(data_type_manager)
            self.mark_stale()

    def get_sorted_data_types_list(self) -> List['DataType']:
        new_list = self.update_data_types_list()
        if self.is_stale:
            return new_list
        else:
            self.data_types_list = new_list
            return list(new_list)

    def update_data_types_list(self):
        if not self.is_stale:
            return self.data_types_list

        self.is_stale = False

        task = IndexerTask()
        threading.Thread(target=task.run).start()

        return task.get_list()

    def mark_stale(self):
        self.is_stale = True
        self.data_types_list = []

class DataTypeIndexUpdateListener:
    def __init__(self):
        pass

    def data_type_manager_invalidated(self, data_type_manager: 'DataTypeManager'):
        threading.Thread(target=lambda: print("Invalidation detected")).start()

    # Other methods similar to the above one...

class IndexerTask(threading.Thread):
    def __init__(self):
        super().__init__()
        self.list = []

    def run(self):
        for manager in DataTypeIndexer.data_type_managers:
            manager.get_all_data_types(self.list)
        self.list.sort(key=DataTypeComparator())

    def get_list(self) -> List['DataType']:
        return self.list

class DataTypeComparator:
    # Method to compare data types...
