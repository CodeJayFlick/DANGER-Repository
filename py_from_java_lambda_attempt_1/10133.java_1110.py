Here is the translation of the given Java code into Python:

```Python
class NamingUtilities:
    MAX_NAME_LENGTH = 60
    MANGLE_CHAR = '_'
    VALID_NAME_SET = {'.', '-', ' ', '_'}

    def __init__(self):
        pass

    @staticmethod
    def isValidName(name: str) -> bool:
        if name is None:
            return False
        if len(name) < 1 or len(name) > NamingUtilities.MAX_NAME_LENGTH:
            return False
        for char in name:
            if not (char.isalnum() or char in NamingUtilities.VALID_NAME_SET):
                return False
        return True

    @staticmethod
    def isValidProjectName(name: str) -> bool:
        if name is None:
            return False
        if name.startswith('.'):
            return False
        if len(name) < 1 or len(name) > NamingUtilities.MAX_NAME_LENGTH:
            return False
        for char in name:
            if not (char.isalnum() or char in NamingUtilities.VALID_NAME_SET):
                return False
        return True

    @staticmethod
    def findInvalidChar(name: str) -> int:
        for i, char in enumerate(name):
            if not (char.isalnum() or char in NamingUtilities.VALID_NAME_SET):
                return i
        return 0

    @staticmethod
    def mangle(name: str) -> str:
        buf = ''
        for char in name:
            if char == NamingUtilities.MANGLE_CHAR:
                buf += NamingUtilities.MANGLE_CHAR + NamingUtilities.MANGLE_CHAR
            elif char.isupper():
                buf += NamingUtilities.MANGLE_CHAR + char.lower()
            else:
                buf += char
        return buf

    @staticmethod
    def demangle(mangled_name: str) -> str:
        buf = ''
        found_mangle = False
        for char in mangled_name:
            if found_mangle:
                found_mangle = False
                if char == NamingUtilities.MANGLE_CHAR:
                    buf += char
                else:
                    buf += char.upper()
            elif char == NamingUtilities.MANGLE_CHAR:
                found_mangle = True
            else:
                buf += char
        return buf

    @staticmethod
    def isValidMangledName(name: str) -> bool:
        for char in name:
            if char.isupper():
                return False
        return True


# Example usage:

naming_utilities = NamingUtilities()
print(naming_utilities.isValidName("test"))  # Returns: True
print(naming_utilities.isValidProjectName("test"))  # Returns: True
mangled_name = naming_utilities.mangle("Test")
print(mangled_name)  # Returns: _tEst
demangled_name = naming_utilities.demangle(mangled_name)
print(demangled_name)  # Returns: Test
```

Please note that Python does not have a direct equivalent to Java's `@Deprecated` annotation. However, you can achieve similar functionality by using docstrings and comments in your code.