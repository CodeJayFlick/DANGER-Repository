class DBTraceChangeSet:
    def read(self, dbh):
        # TODO Auto-generated method stub

    def write(self, dbh, is_recovery_save=False):
        # TODO Auto-generated method stub

    def clear_undo(self, is_checked_out=False):
        # TODO Auto- generated method stub

    def undo(self):
        # TODO Auto-generated method stub

    def redo(self):
        # TODO Auto-generated method stub

    def set_max_undos(self, max_undos):
        # TODO Auto-generated method stub

    def clear_undo(self):
        # TODO Auto-generated method stub

    def start_transaction(self):
        # TODO Auto-generated method stub

    def end_transaction(self, commit=False):
        # TODO Auto-generated method stub

    def data_type_changed(self, id: int):
        # TODO Auto-generated method stub

    def data_type_added(self, id: int):
        # TODO Auto-generated method stub

    def get_data_type_changes(self) -> list[int]:
        return []

    def get_data_type_additions(self) -> list[int]:
        return []

    def category_changed(self, id: int):
        # TODO Auto-generated method stub

    def category_added(self, id: int):
        # TODO Auto-generated method stub

    def get_category_changes(self) -> list[int]:
        return []

    def get_category_additions(self) -> list[int]:
        return []

    def source_archive_changed(self, id: int):
        # TODO Auto-generated method stub

    def source_archive_added(self, id: int):
        # TODO Auto-generated method stub

    def get_source_archive_changes(self) -> list[int]:
        return []

    def get_source_archive_additions(self) -> list[int]:
        return []
