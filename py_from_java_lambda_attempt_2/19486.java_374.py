Here is a translation of the Java code into equivalent Python:

```Python
class EntityAI:
    def __init__(self):
        pass

    @staticmethod
    def register():
        return {"ai": "artificial intelligence", "livingentities": ["has_ai"]}

    def convert(self, entity: dict) -> bool:
        if 'has_ai' in entity['livingentities']:
            return True
        else:
            return False

    def accept_change(self, mode: str):
        if mode == 'set':
            return [bool]
        else:
            return None

    def change(self, event: dict, delta: list, mode: str) -> None:
        for entity in get_expr().get_array(event):
            value = delta[0]  # assuming the first element of delta is the new value
            if 'has_ai' in entity['livingentities']:
                entity['set_ai'] = value

    def get_return_type(self) -> type:
        return bool

    @staticmethod
    def get_property_name():
        return "artificial intelligence"
```

Please note that Python does not have direct equivalent of Java's static block, annotations or generics. The above code is a translation and may require some adjustments based on the actual use case.

Also, this code assumes that you are working with dictionaries to represent entities and events. You would need to replace these with your own data structures if they do not fit your needs.