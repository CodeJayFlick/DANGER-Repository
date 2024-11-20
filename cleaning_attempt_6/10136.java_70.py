import os
from ghidra_framework_store import DatabaseItem, FolderItem, LocalFileSystem
from utilities_util import FileUtilities

class RecoveryDBTest:
    BUFFER_SIZE = 512
    RECORD_COUNT = 1000
    
    SCHEMA = Schema(1, "key", [StringField.INSTANCE], ["field1"])
    
    test_dir = os.path.join(AbstractGenericTest.get_test_directory_path(), 'test')
    file_system = None

    def __init__(self):
        super().__init__()

    @classmethod
    def get_test_directory_path(cls):
        return cls.test_dir

    def setUp(self) -> None:
        FileUtilities.delete_dir(self.test_dir)
        os.mkdir(self.test_dir)
        self.file_system = LocalFileSystem.get_local_file_system(self.test_dir, True, False, False, True)

    def tearDown(self) -> None:
        if self.file_system is not None:
            self.file_system.dispose()
        FileUtilities.delete_dir(self.test_dir)

    def init(self, initial_rec_cnt: int) -> 'DBHandle':
        dbh = DBHandle(self.BUFFER_SIZE)
        bf = self.file_system.create_database("/", "testDb", None, "Test", self.BUFFER_SIZE, None, None)
        dbh.save_as(bf, True, TaskMonitorAdapter.DUMMY_MONITOR)
        dbh.close()
        bf.dispose()

        db_item = (DatabaseItem)self.file_system.get_item("/", "testDb")
        assert not db_item.can_recover()
        bf = db_item.open_for_update(FolderItem.DEFAULT_CHECKOUT_ID)
        dbh = DBHandle(bf, True, TaskMonitorAdapter.DUMMY_MONITOR)

        tx_id = dbh.start_transaction()
        table1 = dbh.create_table("table1", self.SCHEMA)
        self.table_fill(table1, initial_rec_cnt, "initTable1_")
        dbh.end_transaction(tx_id, True)

        tx_id = dbh.start_transaction()
        table2 = dbh.create_table("table2", self.SCHEMA)
        self.table_fill(table2, initial_rec_cnt, "initTable2_")
        dbh.end_transaction(tx_id, True)

        assert dbh.take_recovery_snapshot(None, TaskMonitorAdapter.DUMMY_MONITOR)

        return dbh

    def table_fill(self, table: 'Table', rec_cnt: int, base_name: str) -> None:
        for i in range(rec_cnt):
            rec = self.SCHEMA.create_record(i)
            rec.set_string(0, f"{base_name}{i}")
            table.put_record(rec)

    @classmethod
    def get_test_directory_path(cls):
        return cls.test_dir

class DBHandle:
    def __init__(self, bf: 'BufferFile', buffer_size: int = 512, monitor_adapter: object = TaskMonitorAdapter.DUMMY_MONITOR):
        self.bf = bf
        self.buffer_size = buffer_size
        self.monitor_adapter = monitor_adapter

    @classmethod
    def get_local_file_system(cls) -> LocalFileSystem:
        return cls.file_system

class DBRecord:
    pass

class Table:
    def __init__(self, name: str):
        self.name = name

    def put_record(self, rec: 'DBRecord') -> None:
        # todo implement
        pass

    def get_record_count(self) -> int:
        return 0

    def delete_record(self, i: int) -> None:
        # todo implement
        pass

class Schema:
    def __init__(self, num_fields: int, field_name: str):
        self.num_fields = num_fields
        self.field_name = field_name

    @classmethod
    def get_instance(cls) -> 'Schema':
        return cls(1, "key")

    def create_record(self, i: int) -> 'DBRecord':
        # todo implement
        pass

class BufferFile:
    pass

class TaskMonitorAdapter:
    DUMMY_MONITOR = None

if __name__ == "__main__":
    test_dir = os.path.join(AbstractGenericTest.get_test_directory_path(), 'test')
    file_system = LocalFileSystem.get_local_file_system(test_dir, True, False, False, True)
    
    dbh = RecoveryDBTest().init(1000)

    try:
        assert dbh.undo()
        assert dbh.undo()

        assert dbh.take_recovery_snapshot(None, TaskMonitorAdapter.DUMMY_MONITOR)

        DatabaseItem db_item = (DatabaseItem)file_system.get_item("/", "testDb")
        assert db_item.can_recover()
        BufferFile bf = db_item.open_for_update(FolderItem.DEFAULT_CHECKOUT_ID)
        DBHandle dbh2 = new DBHandle(bf, True, TaskMonitorAdapter.DUMMY_MONITOR)

        Table table1 = dbh2.getTable("table1")
        assert not table1 is None
        assertEquals(1000 / 2, table1.getRecordCount())

        for i in range(0, 1000, 2):
            DBRecord rec = table1.getRecord(i)
            assertNull(rec)

        for i in range(1, 1000, 2):
            DBRecord rec = table1.getRecord(i)
            assertNotNull(rec)
            assertEquals("initTable1_" + str(i), rec.getString(0))

        Table table2 = dbh2.getTable("table2")
        assert not table2 is None
        assertEquals(1000 / 2, table2.getRecordCount())

        for i in range(0, 1000, 2):
            assertNull(table2.getRecord(i))

        for i in range(1, 1000, 2):
            DBRecord rec = table2.getRecord(i)
            assertNotNull(rec)
            assertEquals("initTable2_" + str(i), rec.getString(0))
    finally:
        dbh.close()
        if not dbh2 is None:
            dbh2.close()

# todo implement the rest of the test methods
