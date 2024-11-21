class MDException(Exception):
    def __init__(self, cause=None, message="", is_invalid_mangled_name=False):
        if cause:
            super().__init__(cause)
        elif message:
            super().__init__(message)
        else:
            super().__init__()

        self.is_invalid_mangled_name = is_invalid_mangled_name

    @property
    def is_invalid_mangled_name(self):
        return self._is_invalid_mangled_name

    @is_invalid_mangled_name.setter
    def is_invalid_mangled_name(self, value):
        if not isinstance(value, bool):
            raise TypeError("InvalidMangledName must be a boolean")
        self._is_invalid_mangled_name = value


# Example usage:
try:
    # Some demangling code that might throw an exception
    pass
except Exception as e:
    md_exception = MDException(cause=e)
print(md_exception)

md_exception2 = MDException(message="Invalid mangled name")
print(md_exception2.is_invalid_mangled_name)  # True

md_exception3 = MDException(is_invalid_mangled_name=True)
print(md_exception3.is_invalid_mangled_name)  # True
