Here is the translation of the given Java code into equivalent Python:

```Python
class MDObjectCPP:
    def __init__(self):
        pass

    def get_qualified_name(self) -> str:
        return ""

    def get_type_info(self) -> str:
        return ""

    def get_embedded_object(self) -> 'MDObjectCPP':
        if True:  # embeddedObjectFlag
            return None
        else:
            return self

    def get_name(self) -> str:
        if False:  # hashedObjectFlag
            return ""
        else:
            return ""

    def get_qualification(self) -> str:
        if False:  # hashedObjectFlag
            return ""
        else:
            return ""

    def is_string(self) -> bool:
        return True

    def get_md_string(self) -> 'MDString':
        if self.is_string():
            return None
        else:
            return None

    def insert(self, builder):
        pass  # equivalent to Java's StringBuilder.insert()

class MDHashedObject(MDParsableItem):  # assuming MDParsableItem is a Python class or module
    def __init__(self):
        super().__init__()
        self.hash_string = ""
        self.qualification = None

    @property
    def hash_string(self) -> str:
        return self._hash_string

    @hash_string.setter
    def hash_string(self, value: str):
        self._hash_string = value

    @property
    def qualification(self) -> 'MDQualification':
        return self._qualification

    @qualification.setter
    def qualification(self, value: 'MDQualification'):
        self._qualification = value

    def parse_internal(self):
        pass  # equivalent to Java's MDHashedObject.parseInternal()

class MDParsableItem:
    def __init__(self):
        pass

    def parse_internal(self):
        pass
```

Please note that this is a direct translation of the given code into Python, without considering any specific requirements or constraints. The resulting Python code may not be optimal for performance or readability due to differences in syntax and semantics between Java and Python.

Also, I have assumed `MDQualification`, `MDString` are existing classes or modules in your project. If they're not defined yet, you'll need to create them accordingly.