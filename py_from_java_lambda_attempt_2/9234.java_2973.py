Here is the translation of the given Java code into Python:

```Python
class MasterTable:
    def __init__(self):
        self.master_record = None
        self.dbh = None
        self.db_parms = None
        self.table = None
        self.table_records = []
        self.next_table_num = 0

    def create_master_table(self, dbh) -> None:
        self.dbh = dbh
        self.db_parms = dbh.get_db_parms()
        self.master_record = TableRecord(0, "MASTER", TableRecord.get_schema(), -1)
        try:
            self.master_record.set_root_buffer_id(db_parms[DBParms.MASTER_TABLE_ROOT_BUFFER_ID_PARM])
        except ArrayIndexOutOfBoundsException as e:
            raise IOException("Corrupt database parameters") from e

        self.table = Table(self.dbh, self.master_record)

    def create_table_record(self, name: str, table_schema: Schema, indexed_column: int) -> TableRecord:
        new_table_record = TableRecord(self.next_table_num++, name, table_schema, indexed_column)
        self.table.put_record(new_table_record.get_record())

        db_parms[DBParms.MASTER_TABLE_ROOT_BUFFER_ID_PARM] = self.master_record.get_root_buffer_id()

        self.table_records.append(new_table_record)

    def delete_table_record(self, table_num: int) -> None:
        for i in range(len(self.table_records)):
            if self.table_records[i].get_table_num() == table_num:
                if self.table_records[i].get_root_buffer_id() >= 0:
                    raise IOException("Can not delete non-empty table")
                self.table.delete_record(table_num)
                self.table_records[i].invalidate()

        db_parms[DBParms.MASTER_TABLE_ROOT_BUFFER_ID_PARM] = self.master_record.get_root_buffer_id()
        self.table_records[:] = [record for record in self.table_records if record.get_table_num() != table_num]

    def get_table_records(self) -> list:
        return self.table_records

    def refresh_table_records(self) -> None:
        try:
            master_root_id = db_parms[DBParms.MASTER_TABLE_ROOT_BUFFER_ID_PARM]
            if self.master_record.get_root_buffer_id() != master_root_id:
                self.master_record.set_root_buffer_id(master_root_id)
                self.table.record_changed()
        except ArrayIndexOutOfBoundsException as e:
            raise IOException("Corrupt database parameters") from e

    def flush(self) -> None:
        for record in self.table_records:
            if record.is_dirty():
                self.table.put_record(record.get_record())

    def change_table_name(self, old_name: str, new_name: str) -> None:
        for i in range(len(self.table_records)):
            if old_name == self.table_records[i].get_name():
                self.table_records[i].set_name(new_name)

class TableRecord:
    def __init__(self, table_num: int, name: str, schema: Schema, indexed_column: int):
        self.table_num = table_num
        self.name = name
        self.schema = schema
        self.indexed_column = indexed_column

    @property
    def get_table_num(self) -> int:
        return self.table_num

    @property
    def get_name(self) -> str:
        return self.name

    @name.setter
    def set_name(self, name: str):
        self.name = name

class Table:
    def __init__(self, dbh: object, master_record: TableRecord):
        pass

    def put_record(self, record: DBRecord) -> None:
        pass

    def delete_record(self, table_num: int) -> None:
        pass

    def iterator(self) -> RecordIterator:
        pass

class Schema:
    def __init__(self):
        pass

class TableSchema:
    def get_schema(self) -> Schema:
        return self
```

Note that this translation is not a direct conversion from Java to Python, but rather an interpretation of the given code in terms of Python.