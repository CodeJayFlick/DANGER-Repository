class DataTypeArchiveChangeRecord:
    def __init__(self, type: int, affected_obj: object, old_value: object, new_value: object):
        super().__init__(type, old_value, new_value)
        self.affected_obj = affected_obj

    @property
    def affected_object(self) -> object:
        return self.affected_obj


class DomainObjectChangeRecord:
    pass  # This is a placeholder for the Java class; in Python, we don't need to define it explicitly


# No equivalent of Java's "package" statement in Python
