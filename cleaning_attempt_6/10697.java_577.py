class SaveableString:
    def __init__(self, string=None):
        if not isinstance(string, str) or string is None:
            raise ValueError("Saved string cannot be null")
        self.string = string

    @property
    def fields(self):
        return [str]

    def save(self, obj_storage):
        obj_storage.put_string(self.string)

    def restore(self, obj_storage):
        self.string = obj_storage.get_string()

    def get_schema_version(self):
        return 0

    def is_upgradeable(self, old_schema_version):
        return False

    def upgrade(self, old_obj_storage, old_schema_version, current_obj_storage):
        return False

    @property
    def is_private(self):
        return False

    def __eq__(self, other):
        if self is other:
            return True
        if not isinstance(other, SaveableString) or other.string != self.string:
            return False
        return True

    def __hash__(self):
        return hash(self.string)
