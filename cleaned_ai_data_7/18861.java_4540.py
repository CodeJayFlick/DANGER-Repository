from enum import Enum
import jsonschema


class SchemaType(Enum):
    OBJECT = "object"


class Operation:
    def __init__(self, key: 'ContentsKey'):
        self.key = key


class ContentsKey:
    pass  # This is a placeholder for the actual implementation of ContentsKey in Python.


class Put(Operation):
    def __init__(self, key: 'ContentsKey', contents: dict, expected_contents=None):
        super().__init__(key)
        self.contents = contents
        self.expected_contents = expected_contents


class Delete(Operation):
    def __init__(self, key: 'ContentsKey'):
        super().__init__(key)


class Unchanged(Operation):
    def __init__(self, key: 'ContentsKey'):
        super().__init__(key)

# Example usage:
put_operation = Put(ContentsKey(), {"some_key": "some_value"}, None)
delete_operation = Delete(ContentsKey())
unchanged_operation = Unchanged(ContentsKey())

print(json.dumps({"type": "PUT", "operation": put_operation.__dict__}, indent=4))
