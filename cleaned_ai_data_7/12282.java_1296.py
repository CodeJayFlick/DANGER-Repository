class DataTypeManagerChangeListenerHandler:
    def __init__(self):
        self.listener_list = set()

    def add_data_type_manager_listener(self, listener):
        self.listener_list.add(listener)

    def remove_data_type_manager_listener(self, listener):
        if listener in self.listener_list:
            self.listener_list.remove(listener)

    def category_added(self, dtm, path):
        for listener in self.listener_list.copy():
            listener.category_added(dtm, path)

    def category_moved(self, dtm, old_path, new_path):
        for listener in self.listener_list.copy():
            listener.category_moved(dtm, old_path, new_path)

    def category_removed(self, dtm, path):
        for listener in self.listener_list.copy():
            listener.category_removed(dtm, path)

    def category_renamed(self, dtm, old_path, new_path):
        for listener in self.listener_list.copy():
            listener.category_renamed(dtm, old_path, new_path)
            if not listener.favorites_changed:
                listener.favorites_changed = False

    def data_type_added(self, dtm, path):
        for listener in self.listener_list.copy():
            listener.data_type_added(dtm, path)

    def data_type_changed(self, dtm, path):
        for listener in self.listener_list.copy():
            listener.data_type_changed(dtm, path)

    def data_type_moved(self, dtm, old_path, new_path):
        for listener in self.listener_list.copy():
            listener.data_type_moved(dtm, old_path, new_path)

    def data_type_removed(self, dtm, path):
        for listener in self.listener_list.copy():
            listener.data_type_removed(dtm, path)

    def data_type_renamed(self, dtm, old_path, new_path):
        for listener in self.listener_list.copy():
            listener.data_type_renamed(dtm, old_path, new_path)
            if not listener.favorites_changed:
                listener.favorites_changed = False

    def data_type_replaced(self, dtm, old_path, new_path, new_data_type):
        for listener in self.listener_list.copy():
            listener.data_type_replaced(dtm, old_path, new_path, new_data_type)

    def favorites_changed(self, dtm, path, is_favorite):
        for listener in self.listener_list.copy():
            listener.favorites_changed(dtm, path, is_favorite)

    def source_archive_changed(self, data_type_manager, data_type_source):
        for listener in self.listener_list.copy():
            listener.source_archive_changed(data_type_manager, data_type_source)

    def source_archive_added(self, data_type_manager, data_type_source):
        for listener in self.listener_list.copy():
            listener.source_archive_added(data_type_manager, data_type_source)
