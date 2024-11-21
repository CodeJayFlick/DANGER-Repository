class GroupDBAdapterV0:
    def __init__(self, handle, module_table_name, fragment_table_name, parent_child_table_name):
        self.module_table = handle.get_table(module_table_name)
        self.fragment_table = handle.get_table(fragment_table_name)
        self.parent_child_table = handle.get_table(parent_child_table_name)

        self.test_version(self.module_table, 0, module_table_name)
        self.test_version(self.fragment_table, 0, fragment_table_name)
        self.test_version(self.parent_child_table, 0, parent_child_table_name)

    def create_module(self, parent_module_id, name):
        if get_module_record(name) or get_fragment_record(name):
            raise DuplicateNameException(f"{name} already exists")

        record = TreeManager.MODULE_SCHEMA.create_record(self.module_table.key)
        record.set_string(TreeManager.MODULE_NAME_COL, name)
        self.module_table.put_record(record)

        pc_rec = TreeManager.PARENT_CHILD_SCHEMA.create_record(self.parent_child_table.key)
        pc_rec.set_long_value(TreeManager.PARENT_ID_COL, parent_module_id)
        pc_rec.set_long_value(TreeManager.CHILD_ID_COL, record.key)
        self.parent_child_table.put_record(pc_rec)

        return record

    def create_fragment(self, parent_module_id, name):
        if get_module_record(name) or get_fragment_record(name):
            raise DuplicateNameException(f"{name} already exists")

        key = self.fragment_table.key
        if key == 0:
            key = 1

        record = TreeManager.FRAGMENT_SCHEMA.create_record(key)
        record.set_string(TreeManager.FRAGMENT_NAME_COL, name)
        self.fragment_table.put_record(record)

        pc_rec = TreeManager.PARENT_CHILD_SCHEMA.create_record(self.parent_child_table.key)
        pc_rec.set_long_value(TreeManager.PARENT_ID_COL, parent_module_id)
        # negative value to indicate fragment
        pc_rec.set_long_value(TreeManager.CHILD_ID_COL, -key)
        self.parent_child_table.put_record(pc_rec)

        return record

    def get_fragment_record(self, key):
        return self.fragment_table.get_record(key)

    def get_module_record(self, key):
        return self.module_table.get_record(key)

    def get_parent_child_record(self, parent_id, child_id):
        keys = self.parent_child_table.find_records(parent_id, TreeManager.PARENT_ID_COL)
        for i in range(len(keys)):
            pc_rec = self.parent_child_table.get_record(keys[i])
            if pc_rec.get_long_value(TreeManager.CHILD_ID_COL) == child_id:
                return pc_rec
        return None

    def add_parent_child_record(self, module_id, child_id):
        pc_rec = TreeManager.PARENT_CHILD_SCHEMA.create_record(self.parent_child_table.key)
        pc_rec.set_long_value(TreeManager.PARENT_ID_COL, module_id)
        pc_rec.set_long_value(TreeManager.CHILD_ID_COL, child_id)
        self.parent_child_table.put_record(pc_rec)

        return pc_rec

    def remove_parent_child_record(self, key):
        return self.parent_child_table.delete_record(key)

    def get_parent_child_keys(self, parent_id, indexed_col):
        return self.parent_child_table.find_records(parent_id, indexed_col)

    def get_fragment_record_by_name(self, name):
        keys = self.fragment_table.find_records(name, TreeManager.FRAGMENT_NAME_COL)
        if len(keys) == 0:
            return None
        elif len(keys) > 1:
            raise AssertException(f"Found {len(keys)} fragments named {name}")
        else:
            return self.fragment_table.get_record(keys[0])

    def get_module_record_by_name(self, name):
        keys = self.module_table.find_records(name, TreeManager.MODULE_NAME_COL)
        if len(keys) == 0:
            return None
        elif len(keys) > 1:
            raise AssertException(f"Found {len(keys)} modules named {name}")
        else:
            return self.module_table.get_record(keys[0])

    def get_parent_child_record_by_key(self, key):
        return self.parent_child_table.get_record(key)

    def update_module_record(self, record):
        self.module_table.put_record(record)

    def update_fragment_record(self, record):
        self.fragment_table.put_record(record)

    def update_parent_child_record(self, record):
        self.parent_child_table.put_record(record)

    def create_root_module(self, name):
        record = TreeManager.MODULE_SCHEMA.create_record(0)
        record.set_string(TreeManager.MODULE_NAME_COL, name)
        self.module_table.put_record(record)
        return record

    def remove_fragment_record(self, child_id):
        return self.fragment_table.delete_record(child_id)

    def remove_module_record(self, child_id):
        return self.module_table.delete_record(child_id)

    def test_version(self, table, expected_version, name):
        if table is None:
            raise VersionException(f"{name} not found")
        version_number = table.schema.get_version()
        if version_number != expected_version:
            raise VersionException(
                f"{name}: Expected Version {expected_version}, got {version_number}"
            )
