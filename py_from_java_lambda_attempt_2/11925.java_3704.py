Here is the translation of the Java code into Python:

```Python
class DataTypeArchiveContentHandler:
    DATA_TYPE_ARCHIVE_ICON = None
    PROGRAM_ICON_PATH = "images/closedBookBlue.png"
    DATA_TYPE_ARCHIVES_CONTENT_TYPE = "Archive"

    def create_file(self, fs, userfs, path, name, obj, monitor):
        if not isinstance(obj, DataTypeArchiveDB):
            raise IOException("Unsupported domain object: " + str(obj.__class__.__name__))
        return self.create_file((obj), self.DATA_TYPE_ARCHIVES_CONTENT_TYPE, fs, path, name, monitor)

    def get_immutable_object(self, item, consumer, version, min_change_version, monitor):
        content_type = item.get_content_type()
        if content_type is not None and content_type != self.DATA_TYPE_ARCHIVES_CONTENT_TYPE:
            raise IOException("Unsupported content type: " + str(content_type))
        db_item = DatabaseItem(item)
        bf = None
        dbh = None
        data_type_archive = None
        success = False
        try:
            bf = db_item.open(version, min_change_version)
            dbh = DBHandle(bf)
            open_mode = 0 if version == min_change_version else 1
            data_type_archive = DataTypeArchiveDB(dbh, open_mode, monitor, consumer)
            self.get_data_type_archive_change_set(data_type_archive, bf)
            success = True
            return data_type_archive
        except VersionException as e:
            raise e
        except IOException as e:
            raise e
        except CancelledException as e:
            raise e
        finally:
            if not success and data_type_archive is not None:
                data_type_archive.release(consumer)
            if dbh is not None:
                dbh.close()
            if bf is not None:
                bf.dispose()

    def get_read_only_object(self, item, version, ok_to_upgrade, consumer, monitor):
        content_type = item.get_content_type()
        if content_type is not None and content_type != self.DATA_TYPE_ARCHIVES_CONTENT_TYPE:
            raise IOException("Unsupported content type: " + str(content_type))
        db_item = DatabaseItem(item)
        bf = None
        dbh = None
        data_type_archive = None
        success = False
        try:
            bf = db_item.open(version, ok_to_upgrade)
            dbh = DBHandle(bf, ok_to_upgrade, monitor)
            open_mode = 0 if version == min_change_version else 1
            data_type_archive = DataTypeArchiveDB(dbh, open_mode, monitor, consumer)
            self.get_data_type_archive_change_set(data_type_archive, bf)
            success = True
            return data_type_archive
        except VersionException as e:
            raise e
        except IOException as e:
            raise e
        finally:
            if not success and data_type_archive is not None:
                data_type_archive.release(consumer)
            if dbh is not None:
                dbh.close()
            if bf is not None:
                bf.dispose()

    def get_domain_object(self, item, userfs, checkout_id, ok_to_upgrade, recover, consumer, monitor):
        content_type = item.get_content_type()
        if content_type is not None and content_type != self.DATA_TYPE_ARCHIVES_CONTENT_TYPE:
            raise IOException("Unsupported content type: " + str(content_type))
        db_item = DatabaseItem(item)
        bf = None
        dbh = None
        data_type_archive = None
        success = False
        try:
            bf = db_item.open_for_update(checkout_id, ok_to_upgrade)
            dbh = DBHandle(bf, recover, monitor)
            open_mode = 0 if version == min_change_version else 1
            data_type_archive = DataTypeArchiveDB(dbh, open_mode, monitor, consumer)
            self.get_data_type_archive_change_set(data_type_archive, bf)
            success = True
            return data_type_archive
        except VersionException as e:
            raise e
        finally:
            if not success and data_type_archive is not None:
                data_type_archive.release(consumer)
            if dbh is not None:
                dbh.close()
            if bf is not None:
                bf.dispose()

    def recover_change_set(self, data_type_archive, dbh):
        recovered = False
        change_set = data_type_archive.get_change_set()
        cf = dbh.get_recovery_change_set_file()
        if cf is not None:
            try:
                cfh = DBHandle(cf)
                change_set.read(cfh)
                recovered = True
            finally:
                if cfh is not None:
                    cfh.close()
                cf.dispose()
        return recovered

    def get_data_type_archive_change_set(self, data_type_archive, bf):
        change_set = data_type_archive.get_change_set()
        cf = bf.next_change_data_file(True)
        while cf is not None:
            try:
                cfh = DBHandle(cf)
                change_set.read(cfh)
            finally:
                if cfh is not None:
                    cfh.close()
                cf.dispose()
            cf = bf.next_change_data_file(False)

    def get_change_set(self, item, from_ver, to_ver):
        content_type = item.get_content_type()
        if content_type is not None and content_type != self.DATA_TYPE_ARCHIVES_CONTENT_TYPE:
            raise IOException("Unsupported content type: " + str(content_type))
        db_item = DatabaseItem(item)
        bf = None
        dbh = None
        data_type_archive = None
        try:
            bf = db_item.open(to_ver, from_ver)
            dbh = DBHandle(bf)
            open_mode = 0 if version == min_change_version else 1
            data_type_archive = DataTypeArchiveDB(dbh, open_mode, monitor, consumer)
            return self.get_data_type_archive_change_set(data_type_archive, bf)
        except VersionException as e:
            raise e
        finally:
            if dbh is not None:
                dbh.close()
            if bf is not None:
                bf.dispose()

    def get_domain_object_class(self):
        return DataTypeArchiveDB

    def get_content_type_display_string(self):
        return "Data Type Archive"

    def default_tool_name(self):
        return "CodeBrowser"

    def icon(self):
        if self.DATA_TYPE_ARCHIVE_ICON is None:
            self.DATA_TYPE_ARCHIVE_ICON = ResourceManager.load_image(self.PROGRAM_ICON_PATH)
        return self.DATA_TYPE_ARCHIVE_ICON

    def private_content_type(self):
        return False

    def merge_manager(self, results_obj, source_obj, original_obj, latest_obj):
        return DataTypeArchiveMergeManagerFactory.get_merge_manager(results_obj, source_obj, original_obj, latest_obj)

class ResourceManager:
    @staticmethod
    def load_image(path):
        # implement your image loading logic here
        pass

class DatabaseItem:
    def open(self, version, min_change_version=None):
        # implement your database opening logic here
        pass

    def open_for_update(self, checkout_id):
        # implement your database opening for update logic here
        pass

    def get_content_type(self):
        return None  # implement your content type retrieval logic here

class DBHandle:
    @staticmethod
    def close():
        # implement your closing logic here
        pass

    @staticmethod
    def dispose():
        # implement your disposing logic here
        pass