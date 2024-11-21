Here is the translation of the given Java code into equivalent Python:

```Python
class DataTypeArchiveDBChangeSet:
    def __init__(self):
        self.changed_data_type_ids = set()
        self.changed_category_ids = set()
        self.changed_source_archive_ids = set()
        self.added_data_type_ids = set()
        self.added_category_ids = set()
        self.added_source_archive_ids = set()

    def data_type_changed(self, id):
        if not hasattr(self, 'in_transaction'):
            raise Exception("Not in a transaction")
        lid = long(id)
        if lid not in self.added_data_type_ids and lid not in self.tmp_added_data_type_ids:
            self.tmp_changed_data_type_ids.add(lid)

    def data_type_added(self, id):
        if not hasattr(self, 'in_transaction'):
            raise Exception("Not in a transaction")
        self.tmp_added_data_type_ids.add(long(id))

    def get_data_type_changes(self):
        return list(self.changed_data_type_ids)

    def get_data_type_additions(self):
        return list(self.added_data_type_ids)

    def category_changed(self, id):
        if not hasattr(self, 'in_transaction'):
            raise Exception("Not in a transaction")
        lid = long(id)
        if lid not in self.added_category_ids and lid not in self.tmp_added_category_ids:
            self.tmp_changed_category_ids.add(lid)

    def category_added(self, id):
        if not hasattr(self, 'in_transaction'):
            raise Exception("Not in a transaction")
        self.tmp_added_category_ids.add(long(id))

    def get_category_changes(self):
        return list(self.changed_category_ids)

    def get_category_additions(self):
        return list(self.added_category_ids)

    def source_archive_changed(self, id):
        if not hasattr(self, 'in_transaction'):
            raise Exception("Not in a transaction")
        lid = long(id)
        if lid not in self.added_source_archive_ids and lid not in self.tmp_added_source_archive_ids:
            self.tmp_changed_source_archive_ids.add(lid)

    def source_archive_added(self, id):
        if not hasattr(self, 'in_transaction'):
            raise Exception("Not in a transaction")
        self.tmp_added_source_archive_ids.add(long(id))

    def get_source_archive_additions(self):
        return list(self.added_source_archive_ids)

    def get_source_archive_changes(self):
        return list(self.changed_source_archive_ids)

    def clear_undo(self, isCheckedOut=False):
        if not hasattr(self, 'in_transaction'):
            raise Exception("Cannot clear in a transaction")
        if not isCheckedOut:
            self.changed_data_type_ids.clear()
            self.changed_category_ids.clear()
            self.changed_source_archive_ids.clear()
            self.added_data_type_ids.clear()
            self.added_category_ids.clear()
            self.added_source_archive_ids.clear()

    def start_transaction(self):
        self.redo_list = []
        self.in_transaction = True
        self.tmp_changed_data_type_ids = set()
        self.tmp_changed_category_ids = set()
        self.tmp_changed_source_archive_ids = set()
        self.tmp_added_data_type_ids = set()
        self.tmp_added_category_ids = set()
        self.tmp_added_source_archive_ids = set()

    def end_transaction(self, commit):
        if not hasattr(self, 'in_transaction'):
            return
        self.in_transaction = False
        if commit:
            self.changed_data_type_ids.update(self.tmp_changed_data_type_ids)
            self.changed_category_ids.update(self.tmp_changed_category_ids)
            self.changed_source_archive_ids.update(self.tmp_changed_source_archive_ids)

            self.added_data_type_ids.update(self.tmp_added_data_type_ids)
            self.added_category_ids.update(self.tmp_added_category_ids)
            self.added_source_archive_ids.update(self.tmp_added_source_archive_ids)

            self.undo_list.append(MyChangeDiff(self.tmp_changed_data_type_ids, 
                self.tmp_changed_category_ids, self.tmp_changed_source_archive_ids,
                self.tmp_added_data_type_ids, self.tmp_added_category_ids, 
                self.tmp_added_source_archive_ids))

        if len(self.undo_list) > 4:
            self.undo_list.pop(0)

    def undo(self):
        diff = self.undo_list.pop()
        self.changed_data_type_ids.difference_update(diff.changed_dts)
        self.changed_category_ids.difference_update(diff.changed_cats)
        self.changed_source_archive_ids.difference_update(diff.changed_archives)

        self.added_data_type_ids.difference_update(diff.added_dts)
        self.added_category_ids.difference_update(diff.added_cats)
        self.added_source_archive_ids.difference_update(diff.added_archives)

    def redo(self):
        diff = self.redo_list.pop()
        self.changed_data_type_ids.update(diff.changed_dts)
        self.changed_category_ids.update(diff.changed_cats)
        self.changed_source_archive_ids.update(diff_changed_archives)

        self.added_data_type_ids.update(diff.added_dts)
        self.added_category_ids.update(diff.added_cats)
        self.added_source_archive_ids.update(diff.added_archives)

    def clear_undo_list(self):
        self.undo_list.clear()
        self.redo_list.clear()

class MyChangeDiff:
    def __init__(self, changedDts, changedCats, changedArchives, addedDts, addedCats, addedArchives):
        self.changed_dts = set(changedDts)
        self.changed_cats = set(changedCats)
        self.changed_archives = set(changedArchives)

        self.added_dts = set(addedDts)
        self.added_cats = set(addedCats)
        self.added_archives = set(addedArchives)


# Usage
change_set = DataTypeArchiveDBChangeSet()
change_set.data_type_changed(1)
change_set.category_added(2)

print(change_set.get_data_type_changes())
print(change_set.get_category_additions())

change_set.undo()

print(change_set.get_data_type_changes())
print(change_set.get_category_additions())