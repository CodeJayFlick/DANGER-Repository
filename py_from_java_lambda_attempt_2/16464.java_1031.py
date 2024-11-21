Here is the translation of the Java code into Python:

```Python
class Log:
    def __init__(self):
        self.curr_log_index = None
        self.curr_log_term = None
        self.applied = False
        self.exception = None
        self.create_time = None
        self.enqueue_time = None
        self.byte_size = 0

    @property
    def curr_log_index(self):
        return self._curr_log_index

    @curr_log_index.setter
    def curr_log_index(self, value):
        self._curr_log_index = value

    @property
    def curr_log_term(self):
        return self._curr_log_term

    @curr_log_term.setter
    def curr_log_term(self, value):
        self._curr_log_term = value

    @property
    def applied(self):
        return self._applied

    @applied.setter
    def applied(self, value):
        if not isinstance(value, bool):
            raise TypeError("Applied must be a boolean")
        self._applied = value

    @property
    def exception(self):
        return self._exception

    @exception.setter
    def exception(self, value):
        self._exception = value

    def serialize(self):
        # implement serialization logic here
        pass

    def deserialize(self, buffer):
        # implement deserialization logic here
        pass

    def __eq__(self, other):
        if not isinstance(other, Log):
            return False
        return (self.curr_log_index == other.curr_log_index and 
                self.curr_log_term == other.curr_log_term)

    def __hash__(self):
        return hash((self.curr_log_index, self.curr_log_term))

    def __lt__(self, other):
        if not isinstance(other, Log):
            raise TypeError("Other must be a Log")
        return (self.curr_log_index < other.curr_log_index or 
                (self.curr_log_index == other.curr_log_index and 
                 self.curr_log_term < other.curr_log_term))

    def get_create_time(self):
        return self.create_time

    def set_create_time(self, value):
        if not isinstance(value, int) and not isinstance(value, float):
            raise TypeError("Create time must be an integer or a floating point number")
        self.create_time = value

    def get_enqueue_time(self):
        return self.enqueue_time

    def set_enqueue_time(self, value):
        if not isinstance(value, int) and not isinstance(value, float):
            raise TypeError("Enqueue time must be an integer or a floating point number")
        self.enqueue_time = value

    def get_byte_size(self):
        return self.byte_size

    def set_byte_size(self, value):
        if not isinstance(value, int):
            raise TypeError("Byte size must be an integer")
        self.byte_size = value
```

Note that the `compareTo` method in Java is equivalent to the `<` operator (`__lt__`) in Python. The rest of the methods are either property getters and setters or special methods like `serialize`, `deserialize`, `equals`, `hash`, etc., which do not have direct equivalents in Python.