class IndexTable:
    def __init__(self, primary_table: 'Table', index_table_record: dict) -> None:
        self.db = primary_table.get_db_handle()
        self.primary_table = primary_table
        self.index_table_record = index_table_record
        if not primary_table.use_long_keys() and not primary_table.use_fixed_keys():
            raise AssertionError("Only fixed-length key tables may be indexed")
        self.is_sparse_index = primary_table.get_schema().is_sparse_column(index_table_record['indexed_column'])
        self.primary_table.add_index(self)

    @staticmethod
    def get_index_table(db: 'DBHandle', index_table_record: dict) -> 'IndexTable':
        name = index_table_record['name']
        if not db.has_table(name):
            raise AssertionError(f"Table {name} not found")
        return IndexTable(db.get_table(name), index_table_record)

    @staticmethod
    def create_index_table(primary_table: 'Table', indexed_column: int) -> 'IndexTable':
        if primary_table.get_record_count() != 0:
            raise AssertionError()
        return FieldIndexTable(primary_table, indexed_column)

    def is_consistent(self, monitor: object) -> bool:
        return self.index_table.is_consistent([self.primary_table.get_schema().get_field_names()[indexed_column] for indexed_column in range(len(self.primary_table.get_schema().get_field_names()))], monitor)

    @property
    def primary_table_key_type(self):
        return self.primary_table.get_schema().get_key_field_type()

    @property
    def table_num(self) -> int:
        return self.index_table.get_table_num()

    @property
    def column_index(self) -> int:
        return self.index_column

    def get_statistics(self) -> dict:
        stats = self.index_table.get_statistics()
        stats['index_column'] = self.index_column
        return stats

    def has_record(self, field: 'Field') -> bool:
        return self.index_table.has_record(field)

    @abstractmethod
    def find_primary_keys(self, index_value: 'Field') -> list:
        pass

    @abstractmethod
    def get_key_count(self, index_value: 'Field') -> int:
        pass

    @abstractmethod
    def add_entry(self, record: dict) -> None:
        pass

    @abstractmethod
    def delete_entry(self, old_record: dict) -> None:
        pass

    def delete_all(self):
        self.index_table.delete_all()

    @abstractmethod
    def index_iterator(self) -> object:
        pass

    @abstractmethod
    def index_iterator_before(self, min_field: 'Field', max_field: 'Field') -> object:
        pass

    @abstractmethod
    def index_iterator_after(self, start_field: 'Field') -> object:
        pass

    @abstractmethod
    def key_iterator(self) -> object:
        pass

    @abstractmethod
    def key_iterator_before(self, min_field: 'Field', max_field: 'Field', before: bool) -> object:
        pass

    @abstractmethod
    def key_iterator_after(self, start_field: 'Field') -> object:
        pass


class FieldIndexTable(IndexTable):
    def __init__(self, primary_table: 'Table', indexed_column: int) -> None:
        super().__init__(primary_table, {'name': '', 'indexed_column': indexed_column})
