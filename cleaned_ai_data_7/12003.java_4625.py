class TreeDBAdapterV0:
    def __init__(self, handle):
        self.handle = handle
        try:
            tree_table_name = 'TreeTable'
            self.tree_table = self.handle.get_table(tree_table_name)
            if not self.tree_table:
                raise VersionException("Tree table not found")
            version_number = self.tree_table.schema.version
            if version_number != 0:  # assuming the expected version is 0 in this case
                raise VersionException(VersionException.NEWER_VERSION, False)
        except Exception as e:
            print(f"An error occurred during initialization. Error message: {str(e)}")

    def create_record(self, name):
        try:
            record = self.tree_table.create_record()
            record['name'] = name
            record['modification_num'] = 0
            self.tree_table.put_record(record)
            return record
        except Exception as e:
            print(f"An error occurred during creating a new record. Error message: {str(e)}")

    def delete_record(self, tree_id):
        try:
            if self.tree_table.delete_record(tree_id):
                # assuming the following tables need to be deleted when a record is removed
                module_table_name = f'module_{tree_id}'
                parent_child_table_name = f'parent_child_{tree_id}'
                fragment_table_name = f'fragment_{tree_id}'

                if self.handle.has_table(module_table_name):
                    self.handle.delete_table(module_table_name)
                if self.handle.has_table(parent_child_table_name):
                    self.handle.delete_table(parent_child_table_name)
                if self.handle.has_table(fragment_table_name):
                    self.handle.delete_table(fragment_table_name)

                return True
            else:
                return False
        except Exception as e:
            print(f"An error occurred during deleting a record. Error message: {str(e)}")

    def get_record(self, tree_id):
        try:
            return self.tree_table.get_record(tree_id)
        except Exception as e:
            print(f"An error occurred during getting a record by ID. Error message: {str(e)}")

    def get_record_by_name(self, name):
        try:
            keys = self.tree_table.find_records(StringField(name), 'name')
            if len(keys) == 0:
                return None
            elif len(keys) > 1:
                raise AssertException(f"Found {len(keys)} trees named {name}")
            else:
                return self.tree_table.get_record(keys[0])
        except Exception as e:
            print(f"An error occurred during getting a record by name. Error message: {str(e)}")

    def get_records(self):
        try:
            return self.tree_table.iterator()
        except Exception as e:
            print(f"An error occurred during iterating over records. Error message: {str(e)}")

    def update_record(self, record):
        try:
            self.tree_table.put_record(record)
        except Exception as e:
            print(f"An error occurred during updating a record. Error message: {str(e)}")
