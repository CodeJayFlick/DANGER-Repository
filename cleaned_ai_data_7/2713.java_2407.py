class UnsatisfiedFieldsException(Exception):
    def __init__(self, missing):
        super().__init__("There are fields without suitable constructors: " + str(missing))
        self.missing = frozenset(missing)

    @property
    def missing(self):
        return self._missing

unsatisfied_fields_exception = UnsatisfiedFieldsException({"Class1", "Class2"})
print(unsatisfied_fields_exception.get_missing())
