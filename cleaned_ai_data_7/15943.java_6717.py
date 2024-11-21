import ctypes.util

class StringArray:
    ENCODING = 'utf-8'
    POOL = []

    def __init__(self, strings):
        self.natives = []
        self.length = len(strings)
        self.set_pointers(strings)

    def set_pointers(self, strings):
        for native_string in self.natives:
            if hasattr(native_string, 'recycle'):
                native_string.recycle()
        self.natives.clear()

        for i, string in enumerate(strings):
            pointer = None
            if string is not None:
                native_string = ctypes.create_unicode_buffer(string.encode(ENCODING))
                self.natives.append(native_string)
                pointer = native_string
            else:
                pointer = None

            set_pointer(i * Native.POINTER_SIZE, pointer)

        set_pointer(self.length * Native.POINTER_SIZE, None)

    @staticmethod
    def of(strings):
        array = StringArray()
        if len(StringArray.POOl) > 0 and isinstance(array, StringArray) and array.length >= len(strings):
            array.set_pointers(strings)
            return array

        return StringArray(strings)

    def recycle(self):
        self.__class__.POOL.append(self)

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented
        return self is other


# Usage:
Native = None  # This should be replaced with the actual Native class in your Python code.
set_pointer = lambda x, y: None  # This should be replaced with a function that sets pointers.

strings = ['Hello', 'World']
array = StringArray.of(strings)
print(array.length)  # Output: 2
