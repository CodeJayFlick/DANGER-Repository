class CategoryDBAdapterV0:
    CATEGORY_TABLE_NAME = "Categories"
    V0_CATEGORY_NAME_COL = 0
    V0_CATEGORY_PARENT_COL = 1
    V0_SCHEMA = {
        'Category ID': {'type': int, 'name': 'Name', 'parent_id': 'Parent ID'}
    }

    def __init__(self, handle, open_mode):
        if open_mode == "CREATE":
            self.table = handle.create_table(self.CATEGORY_TABLE_NAME, self.V0_SCHEMA)
        else:
            try:
                self.table = handle.get_table(self.CATEGORY_TABLE_NAME)
                if not self.table:
                    raise VersionException("Missing Table: {}".format(self.CATEGORY_TABLE_NAME))
                elif self.table['Category ID']['version'] != 0:
                    raise VersionException("Expected version 0 for table {} but got {}".format(
                        self.CATEGORY_TABLE_NAME, self.table['Category ID']['version']
                    ))
            except Exception as e:
                print(e)

    def get_record(self, category_id):
        try:
            return self.table[category_id]
        except KeyError:
            raise IOException("Record not found")

    def get_records_with_parent(self, category_id):
        try:
            parent = [rec for rec in self.table if rec['parent_id'] == str(category_id)]
            return parent
        except Exception as e:
            print(e)

    def update_record(self, category_id, parent_id, name):
        try:
            record = {**self.V0_SCHEMA['Category ID'], 'name': name, 'parent_id': parent_id}
            self.table[category_id] = record
        except Exception as e:
            print(e)

    def put_record(self, record):
        try:
            self.table.update({record})
        except Exception as e:
            print(e)

    def create_category(self, name, parent_id):
        key = len(self.table) + 1 if not self.table else max(list(self.table.keys())) + 1
        record = {**self.V0_SCHEMA['Category ID'], 'name': name, 'parent_id': str(parent_id)}
        self.table[key] = record
        return record

    def remove_category(self, category_id):
        try:
            del self.table[category_id]
            return True
        except KeyError:
            raise IOException("Record not found")

    def get_root_record(self):
        parent_records = [rec for rec in self.table if str(rec['parent_id']) == '-1']
        if len(parent_records) != 1:
            raise IOError("Found {} entries for root category".format(len(parent_records)))
        return {**self.V0_SCHEMA['Category ID'], **parent_records[0]}

    def get_record_count(self):
        return len(self.table)
