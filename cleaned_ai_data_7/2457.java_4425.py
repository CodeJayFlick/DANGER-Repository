class AbstractDBTraceVariableSymbol:
    DATATYPE_COLUMN_NAME = "DataType"
    STORAGE_COLUMN_NAME = "Storage"
    COMMENT_COLUMN_NAME = "Comment"

    datatype_column = None
    storage_column = None
    comment_column = None

    def __init__(self, manager, store, record):
        super().__init__(manager, store, record)

    def fresh(self, created=False):
        if not created:
            self.datatype = self.manager.data_type_manager.get_data_type(self.data_type_id)
            storage_entry = self.manager.storage_store.get_object_at(self.storage_id)
            if storage_entry is None:
                raise IOException("Database is corrupt. Cannot find VariableStorage entry " + str(self.storage_id))
            self.storage = storage_entry.get_storage()
            self.address = AddressSpace.VARIABLE_SPACE.get_address(self.storage_id)

    def set(self, name, parent, dt, s, source):
        super().set(name, parent, source)
        self.data_type_id = self.manager.data_type_manager.get_resolved_id(dt)
        self.datatype = self.manager.data_type_manager.get_data_type(self.data_type_id)
        self.storage_id = self.manager.find_or_record_variable_storage(s)
        self.update([self.datatype_column, self.storage_column])

    def adjust_storage(self, s):
        return s

    def __str__(self):
        try:
            with LockHold.lock(self.manager.lock.read_lock()):
                return f"[{self.get_data_type().name} {self.name}@{self.variable_storage}]"
        except Exception as e:
            print(f"Error: {e}")

    @property
    def address(self):
        try:
            with LockHold.lock(self.manager.lock.read_lock()):
                return self._address
        except Exception as e:
            print(f"Error: {e}")
            return None

    @property
    def comment(self):
        try:
            with LockHold.lock(self.manager.lock.read_lock()):
                return self._comment
        except Exception as e:
            print(f"Error: {e}")
            return None

    @comment.setter
    def comment(self, value):
        try:
            with LockHold.lock(self.manager.lock.write_lock()):
                self._comment = value
                self.update([self.comment_column])
        except Exception as e:
            print(f"Error: {e}")

    @property
    def datatype(self):
        return self._datatype

    @datatype.setter
    def datatype(self, dt):
        try:
            with LockHold.lock(self.manager.lock.write_lock()):
                self.data_type_id = self.manager.data_type_manager.get_resolved_id(dt)
                self.datatype = self.manager.data_type_manager.get_data_type(self.data_type_id)
                self.update([self.datatype_column])
        except Exception as e:
            print(f"Error: {e}")

    @property
    def storage(self):
        return self._storage

    @storage.setter
    def storage(self, s):
        try:
            with LockHold.lock(self.manager.lock.write_lock()):
                self.storage_id = self.manager.find_or_record_variable_storage(s)
                self.update([self.storage_column])
        except Exception as e:
            print(f"Error: {e}")

    def do_set_datatype(self, dt):
        self.data_type_id = self.manager.data_type_manager.get_resolved_id(dt)
        self.datatype = self.manager.data_type_manager.get_data_type(self.data_type_id)
        self.update([self.datatype_column])

    def do_set_storage(self, s):
        try:
            with LockHold.lock(self.manager.lock.write_lock()):
                self.storage = s
                self.update([self.storage_column])
        except Exception as e:
            print(f"Error: {e}")

    @property
    def variable_storage(self):
        return self._variable_storage

    def get_function(self):
        pass  # Abstract method, must be implemented by subclass

    def set_comment(self, value):
        try:
            with LockHold.lock(self.manager.lock.write_lock()):
                self.comment = value
                self.update([self.comment_column])
        except Exception as e:
            print(f"Error: {e}")

    @property
    def comment(self):
        try:
            with LockHold.lock(self.manager.lock.read_lock()):
                return self._comment
        except Exception as e:
            print(f"Error: {e}")
            return None

    # ... other methods ...
