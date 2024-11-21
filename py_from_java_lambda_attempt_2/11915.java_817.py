Here is the translation of the given Java code into Python:

```Python
class SourceArchiveDB:
    def __init__(self, dt_mgr, cache, adapter, record):
        self.dt_mgr = dt_mgr
        self.adapter = adapter
        self.record = record
        self.source_id = UniversalID(record.key)
        self.lock = dt_mgr.lock

    def get_source_archive_id(self):
        if self.is_local():
            universal_id = self.dt_mgr.get_universal_id()
            return universal_id if universal_id else self.source_id
        return self.source_id

    def is_local(self):
        return record.key == DataTypeManager.LOCAL_ARCHIVE_KEY

    def get_domain_file_id(self):
        if self.is_local():
            return self.dt_mgr.domain_file_id
        return record.get_string(SourceArchiveAdapter.ARCHIVE_ID_DOMAIN_FILE_ID_COL)

    def get_archive_type(self):
        if self.is_local():
            return self.dt_mgr.type
        byte_value = record.get_byte_value(SourceArchiveAdapter.ARCHIVE_ID_TYPE_COL)
        return ArchiveType(byte_value)

    def get_name(self):
        if self.is_local():
            return self.dt_mgr.name
        return record.get_string(SourceArchiveAdapter.ARCHIVE_ID_NAME_COL)

    def refresh(self):
        try:
            rec = self.adapter.get_record(self.key)
            if rec is not None:
                self.record = rec
                return True
        except Exception as e:
            self.dt_mgr.db_error(e)
        return False

    @property
    def last_sync_time(self):
        return record.get_long_value(SourceArchiveAdapter.ARCHIVE_ID_LAST_SYNC_TIME_COL)

    @property
    def is_dirty(self):
        return record.get_boolean_value(SourceArchiveAdapter.ARCHIVE_ID_DIRTY_FLAG_COL)

    def set_last_sync_time(self, sync_time):
        self.lock.acquire()
        try:
            if not self.is_valid():
                raise Exception("Invalid source archive")
            record.set_long_value(SourceArchiveAdapter.ARCHIVE_ID_LAST_SYNC_TIME_COL, sync_time)
            self.adapter.update_record(record)
            self.dt_mgr.source_archive_changed(self.get_source_archive_id())
        except Exception as e:
            self.dt_mgr.db_error(e)
        finally:
            self.lock.release()

    def set_dirty_flag(self, is_dirty):
        self.lock.acquire()
        try:
            if not self.is_valid():
                raise Exception("Invalid source archive")
            record.set_boolean_value(SourceArchiveAdapter.ARCHIVE_ID_DIRTY_FLAG_COL, is_dirty)
            self.adapter.update_record(record)
            self.dt_mgr.source_archive_changed(self.get_source_archive_id())
        except Exception as e:
            self.dt_mgr.db_error(e)
        finally:
            self.lock.release()

    def set_name(self, new_name):
        if self.name == new_name:
            return
        self.lock.acquire()
        try:
            if not self.is_valid():
                raise Exception("Invalid source archive")
            record.set_string(SourceArchiveAdapter.ARCHIVE_ID_NAME_COL, new_name)
            self.adapter.update_record(record)
            self.dt_mgr.source_archive_changed(self.get_source_archive_id())
        except Exception as e:
            self.dt_mgr.db_error(e)
        finally:
            self.lock.release()

    def __str__(self):
        return self.name
```

Note: The `UniversalID` class, `DataTypeManager`, and the `SourceArchiveAdapter` are not provided in your code. You would need to implement these classes or replace them with Python equivalents for this translation to work correctly.