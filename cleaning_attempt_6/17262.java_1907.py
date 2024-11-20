class SetStorageGroupOperator:
    def __init__(self, token_int_type):
        self.operator_type = "SET_STORAGE_GROUP"
        super().__init__(token_int_type)

    @property
    def path(self):
        return self._path

    @path.setter
    def set_path(self, value):
        self._path = value

    def generate_physical_plan(self, generator):
        from physical import SetStorageGroupPlan
        return SetStorageGroupPlan(self.path)
