Here is the translation of the given Java code into equivalent Python:

```Python
from datetime import date
import universalid as UniversalID

class DataTypeSyncInfo:
    def __init__(self, ref_dt: 'DataType', source_dtm: 'DataTypeManager'):
        self.ref_dt = ref_dt
        self.source_dtm = source_dtm
        dt_id = ref_dt.get_universal_id()
        if source_dtm and dt_id:
            self.source_dt = source_dtm.get_data_type(source_dtm.get_local_source_archive(), dt_id)
        else:
            self.source_dt = None
        self.sync_state = self.compute_sync_state()

    def get_sync_state(self):
        return self.sync_state

    def compute_sync_state(self):
        if not self.source_dtm:
            return 'UNKNOWN'
        elif not self.source_dt:
            return 'ORPHAN'
        elif self.can_update():
            return 'CONFLICT' if self.can_commit() else 'UPDATE'
        elif self.can_commit():
            return 'COMMIT'
        return 'IN_SYNC'

    def can_update(self):
        if not self.source_dt:
            return False
        if self.source_dt.get_last_change_time() == self.ref_dt.get_last_change_time_in_source_archive():
            return False
        # Special case where user committed changes to archive, but then didn't save the archive.
        elif self.ref_dt.get_last_change_time_in_source_archive() > self.source_dt.get_last_change_time():
            return False
        return True

    def can_commit(self):
        if not self.source_dt:
            return True
        if self.ref_dt.get_last_change_time() != self.ref_dt.get_last_change_time_in_source_archive():
            # Normal commit case.
            return True
        elif self.ref_dt.get_last_change_time_in_source_archive() > self.source_dt.get_last_change_time():
            # Our previous commit was not saved.
            return True
        else:
            return False

    def can_revert(self):
        return bool(self.source_dt) and self.can_commit()

    def commit(self):
        if self.can_commit():
            DataTypeSynchronizer.commit_assuming_transactions_open(self.source_dtm, self.ref_dt)

    def update(self):
        if self.can_update():
            DataTypeSynchronizer.update_assuming_transactions_open(self.ref_dt.get_data_type_manager(), self.source_dt)

    def revert(self):
        if self.can_revert():
            self.update()

    def disassociate(self):
        ref_dtm = self.ref_dt.get_data_type_manager()
        ref_dtm.disassociate(self.ref_dt)

    @property
    def source_dt_path(self):
        return "" if not self.source_dt else self.source_dt.path_name

    @property
    def ref_dt_path(self):
        return self.ref_dt.path_name

    def get_last_change_time(self, use_source: bool = False) -> int:
        dt = self.source_dt if use_source else self.ref_dt
        return 0xFFFFFFFFFFFFFFFF if not self.can_update() else dt.get_last_change_time()

    def get_last_change_string(self, use_source: bool = False):
        dt = self.source_dt if use_source else self.ref_dt
        return "" if not self.can_update() else date.fromtimestamp(dt.get_last_change_time()).strftime("%Y-%m-%d %H:%M:%S")

    def get_last_sync_string(self) -> str:
        return date.fromtimestamp(self.ref_dt.get_last_change_time_in_source_archive()).strftime("%Y-%m-%d %H:%M:%S")

    @property
    def last_sync_time(self):
        return self.ref_dt.get_last_change_time_in_source_archive()

    def get_date_string(self, dt: int) -> str:
        if not dt:
            return ""
        return date.fromtimestamp(dt).strftime("%Y-%m-%d %H:%M:%S")

    @property
    def ref_data_type(self):
        return self.ref_dt

    @property
    def source_data_type(self):
        return self.source_dt

    def has_change(self) -> bool:
        if not self.source_dt:
            return True
        elif not DataTypeSynchronizer.names_are_equivalent(self.source_dt, self.ref_dt):
            return True
        elif self.ref_dt.description != self.source_dt.description:
            return True
        dt = self.source_dt.clone(self.ref_dt.get_data_type_manager())
        return not dt.is_equivalent(self.ref_dt)

    def sync_times(self) -> None:
        if not self.source_dt:
            raise ValueError("Can't sync datatypes with missing source datatype.")
        last_change_time = self.source_dt.get_last_change_time()
        self.ref_dt.set_last_change_time_in_source_archive(last_change_time)
        self.ref_dt.set_last_change_time(last_change_time)

    @property
    def name(self):
        return self.ref_dt.name

class DataType:
    pass

class DataTypeManager:
    pass

class UniversalID:
    pass

class DateUtils:
    @staticmethod
    def format_date_timestamp(date: date) -> str:
        # implement this method as per your requirement.
        pass

class DataTypeSynchronizer:
    @staticmethod
    def commit_assuming_transactions_open(dtm, dt):
        # implement this method as per your requirement.
        pass

    @staticmethod
    def update_assuming_transactions_open(dt_manager: 'DataTypeManager', dt: 'DataType'):
        # implement this method as per your requirement.
        pass
```

Please note that you need to define the classes `DataType`, `DataTypeManager`, and `UniversalID` based on their Java counterparts. Also, you may need to modify some methods according to Python's syntax and semantics.