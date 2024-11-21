class ArrayDBAdapter:
    SCHEMA = 'ArrayDBAdapterV1'
    ARRAY_DT_ID_COL = 0
    ARRAY_DIM_COL = 1
    ARRAY_ELEMENT_LENGTH_COL = 2
    ARRAY_CAT_COL = 3

    @staticmethod
    def get_adapter(handle, open_mode):
        if open_mode == "CREATE":
            return ArrayDBAdapterV1(handle, True)
        try:
            return ArrayDBAdapterV1(handle, False)
        except VersionException as e:
            if not e.is_upgradable() or open_mode == "UPDATE":
                raise
            adapter = find_readonly_adapter(handle)
            if open_mode == "UPGRADE":
                adapter = upgrade(handle, adapter)
            return adapter

    @staticmethod
    def find_readonly_adapter(handle):
        try:
            return ArrayDBAdapterV0(handle)
        except VersionException as e:
            print(f"Error: {e}")

    @staticmethod
    def upgrade(handle, old_adapter):
        tmp_handle = DBHandle()
        id = tmp_handle.start_transaction()
        adapter = None
        try:
            adapter = ArrayDBAdapterV1(tmp_handle, True)
            records = old_adapter.get_records()
            for rec in records:
                adapter.update_record(rec)
            old_adapter.delete_table(handle)
            new_adapter = ArrayDBAdapterV1(handle, True)
            records = adapter.get_records()
            for rec in records:
                new_adapter.update_record(rec)
        finally:
            tmp_handle.end_transaction(id, True)
            tmp_handle.close()

    @abstractmethod
    def create_record(self, data_type_id, number_of_elements, length, category_id):
        pass

    @abstractmethod
    def get_record(self, array_id):
        pass

    @abstractmethod
    def get_records(self):
        pass

    @abstractmethod
    def remove_record(self, data_id):
        pass

    @abstractmethod
    def update_record(self, record):
        pass

    @abstractmethod
    def delete_table(self, handle):
        pass

    @abstractmethod
    def get_record_ids_in_category(self, category_id):
        pass


class ArrayDBAdapterV0:
    def __init__(self, handle):
        self.handle = handle

    def create_record(self, data_type_id, number_of_elements, length, category_id):
        # implement the method here
        pass

    def get_record(self, array_id):
        # implement the method here
        pass

    def get_records(self):
        # implement the method here
        pass

    def remove_record(self, data_id):
        # implement the method here
        pass

    def update_record(self, record):
        # implement the method here
        pass

    def delete_table(self, handle):
        # implement the method here
        pass

    def get_record_ids_in_category(self, category_id):
        # implement the method here
        pass


class ArrayDBAdapterV1:
    def __init__(self, handle, create_mode=False):
        self.handle = handle
        self.create_mode = create_mode

    def create_record(self, data_type_id, number_of_elements, length, category_id):
        # implement the method here
        pass

    def get_record(self, array_id):
        # implement the method here
        pass

    def get_records(self):
        # implement the method here
        pass

    def remove_record(self, data_id):
        # implement the method here
        pass

    def update_record(self, record):
        # implement the method here
        pass

    def delete_table(self, handle):
        # implement the method here
        pass

    def get_record_ids_in_category(self, category_id):
        # implement the method here
        pass


class DBHandle:
    def start_transaction(self):
        return 0

    def end_transaction(self, id, commit=False):
        if not commit:
            print("Transaction rolled back")

    def close(self):
        print("DB handle closed")
