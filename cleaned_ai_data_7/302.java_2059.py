class DomainFolderChangeAdapter:
    def domain_file_added(self, file):
        pass

    def domain_folder_added(self, folder):
        pass

    def domain_folder_removed(self, parent, name):
        pass

    def domain_file_removed(self, parent, name, file_id):
        pass

    def domain_folder_renamed(self, folder, old_name):
        pass

    def domain_file_renamed(self, file, old_name):
        pass

    def domain_folder_moved(self, folder, old_parent):
        pass

    def domain_file_moved(self, file, old_parent, old_name):
        pass

    def domain_folder_set_active(self, folder):
        pass

    def domain_file_status_changed(self, file, file_id_set):
        pass

    def domain_file_object_replaced(self, file, old_object):
        pass

    def domain_file_object_opened_for_update(self, file, object):
        pass

    def domain_file_object_closed(self, file, object):
        pass
