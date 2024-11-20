Here is the translation of the Java code into Python:

```Python
class ProjectDataTypeManager:
    def __init__(self):
        pass

    def set_data_type_archive(self, dt_archive):
        self.data_type_archive = dt_archive

    def get_name(self):
        return self.data_type_archive.get_domain_file().get_name()

    def get_pointer(self, dt):
        return PointerDataType.get_pointer(dt, self.data_type_archive.default_pointer_size)

    def set_name(self, name):
        if not name or len(name) == 0:
            raise InvalidNameException("Name is invalid: " + name)
        self.data_type_archive.set_name(name)
        category_renamed(CategoryPath.ROOT, None)

    def data_type_changed(self, dt, is_auto_change):
        super().data_type_changed(dt, is_auto_change)
        # TODO
        self.data_type_archive.data_type_changed(get_id(dt), 
            DataTypeArchiveChangeManager.DOCR_DATA_TYPE_CHANGED, is_auto_change, None, dt)

    def data_type_added(self, new_dt, original_dt):
        super().data_type_added(new_dt, original_dt)
        # TODO
        self.data_type_archive.data_type_added(get_id(new_dt),
            DataTypeArchiveChangeManager.DOCR_DATA_TYPE_ADDED, None, new_dt)

    def data_type_replaced(self, existing_dt_id, path, replacement_dt):
        super().data_type_replaced(existing_dt_id, path, replacement_dt)
        # TODO
        self.data_type_archive.data_type_changed(existing_dt_id,
            DataTypeArchiveChangeManager.DOCR_DATA_TYPE_REPLACED, False, path, 
            replacement_dt)

    def data_type_deleted(self, deleted_id, path):
        super().data_type_deleted(deleted_id, path)
        # TODO
        self.data_type_archive.data_type_changed(deleted_id,
            DataTypeArchiveChangeManager.DOCR_DATA_TYPE_REMOVED, False, path, None)

    def data_type_moved(self, dt, old_path, new_path):
        super().data_type_moved(dt, old_path, new_path)
        category = get_category(old_path.get_category_path())
        # TODO
        self.data_type_archive.data_type_changed(get_id(dt),
            DataTypeArchiveChangeManager.DOCR_DATA_TYPE_MOVED, False, category, dt)

    def data_type_name_changed(self, dt, old_name):
        super().data_type_name_changed(dt, old_name)
        # TODO
        self.data_type_archive.data_type_changed(get_id(dt), 
            DataTypeArchiveChangeManager.DOCR_DATA_TYPE_RENAMED, False, old_name, dt)

    def category_created(self, new_category):
        super().category_created(new_category)
        # TODO
        self.data_type_archive.category_added(new_category.get_id(),
            DataTypeArchiveChangeManager.DOCR_CATEGORY_ADDED, new_category.get_parent(), new_category)

    def category_renamed(self, old_path, category):
        super().category_renamed(old_path, category)
        # TODO
        self.data_type_archive.category_changed(category.get_id(),
            DataTypeArchiveChangeManager.DOCR_CATEGORY_RENAMED, old_path.get_name(), category)

    def category_removed(self, parent, name, id):
        super().category_removed(parent, name, id)
        # TODO
        self.data_type_archive.category_changed(id,
            DataTypeArchiveChangeManager.DOCR_CATEGORY_REMOVED, parent, name)

    def category_moved(self, old_path, category):
        super().category_moved(old_path, category)
        # TODO
        self.data_type_archive.category_changed(category.get_id(),
            DataTypeArchiveChangeManager.DOCR_CATEGORY_MOVED, old_path.get_parent(), category)

    def favorites_changed(self, dt, is_favorite):
        super().favorites_changed(dt, is_favorite)

    def replace_data_type_ids(self, old_dt_id, new_dt_id):
        # TODO
        pass

    def delete_data_type_ids(self, deleted_ids):
        for id in deleted_ids:
            # TODO
            pass

    def start_transaction(self, description):
        return self.data_type_archive.start_transaction(description)

    def flush_events(self):
        self.data_type_archive.flush_events()

    def end_transaction(self, transaction_id, commit):
        self.data_type_archive.end_transaction(transaction_id, commit)

    def get_domain_file(self):
        return self.data_type_archive.get_domain_file()

    def get_domain_file_id(self):
        domain_file = self.get_domain_file()
        if domain_file:
            return domain_file.get_file_id()
        else:
            return None

    def get_path(self):
        domain_file = self.get_domain_file()
        if domain_file:
            return domain_file.get_pathname()
        else:
            return None

    def get_type(self):
        return ArchiveType.PROJECT

    def archive_ready(self, open_mode, monitor):
        if open_mode == DBConstants.UPGRADE:
            do_source_archive_updates(None, monitor)
            migrate_old_flex_array_components_if_required(monitor)

    def close(self):
        # cannot close a project data type manager
        pass


class PointerDataType:
    @staticmethod
    def get_pointer(dt, pointer_size):
        return None

# TODO: implement these methods and classes