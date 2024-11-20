class CompilerSpecID:
    def __init__(self, compiler_id):
        self.compiler_id = compiler_id

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        if not isinstance(value, str) or len(value.strip()) == 0:
            raise ValueError("Compiler ID cannot be null or empty")
        self._id = value

    def __str__(self):
        return self.id

    def __eq__(self, other):
        if not isinstance(other, CompilerSpecID):
            return False
        return self.id.lower() == other.id.lower()

    def __lt__(self, other):
        return self.id.lower() < other.id.lower()
