class FileSystemInfo:
    def __init__(self):
        self.type = None
        self.description = ""
        self.factory = None
        self.priority = 0

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        if not isinstance(value, str) or len(value) > 1:
            raise ValueError("Type must be a short lowercase string")
        self._type = value

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        self._description = value if value else ""

    @property
    def factory(self):
        return self._factory

    @factory.setter
    def factory(self, value):
        if not isinstance(value, type) or issubclass(value, GFileSystemFactory):
            raise ValueError("Factory must be a subclass of GFileSystemFactory")
        self._factory = value

    @property
    def priority(self):
        return self._priority

    @priority.setter
    def priority(self, value):
        if not isinstance(value, int) or (value < PRIORITY_LOWEST and value > PRIORITY_HIGH):
            raise ValueError("Priority must be an integer between -10 and 10")
        self._priority = value


PRIORITY_DEFAULT = 0
PRIORITY_HIGH = 10
PRIORITY_LOW = -10
PRIORITY_LOWEST = float('-inf')
