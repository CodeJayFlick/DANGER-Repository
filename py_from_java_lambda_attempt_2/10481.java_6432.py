Here is the translation of the given Java code into Python:

```Python
class LongAttribute:
    def __init__(self, name: str, set):
        self.name = name
        self.set = set
        #self.values = [0] * len(set)
        self.values = {}

    def set_value(self, o, value):
        if isinstance(o, dict) and 'key' in o:
            self.update()
            self.values[o['key']] = value

    def get_value(self, o):
        try:
            return self.values.get(o['key'])
        except KeyError as e:
            raise NoValueException("KeyedObject does not belong to the owningSet.")

class LongComparator:
    def compare(self, object1: dict, object2: dict) -> int:
        value1 = 0
        value2 = 0

        try:
            value1 = self.get_value(object1)
            value2 = self.get_value(object2)

            if value1 < value2:
                return -1
            elif value1 > value2:
                return 1
            else:
                if object1['key'] < object2['key']:
                    return -1
                elif object1['key'] > object2['key']:
                    return 1
                else:
                    return 0

        except NoValueException as e:
            try:
                value2 = self.get_value(object2)
                if value1 < value2:
                    return -1
                elif value1 > value2:
                    return 1
                else:
                    if object1['key'] < object2['key']:
                        return -1
                    elif object1['key'] > object2['key']:
                        return 1
                    else:
                        return 0

            except NoValueException as e:
                if object1['key'] < object2['key']:
                    return -1
                elif object1['key'] > object2['key']:
                    return 1
                else:
                    return 0


class AttributeManager:
    LONG_TYPE = "Long"


def main():
    # Create a set of KeyedObjects
    set = [{"key": i, "value": i} for i in range(10)]

    attribute = LongAttribute("attribute", set)

    # Set values to the attribute
    for o in set:
        attribute.set_value(o, o['value'])

    # Sort the set based on the attribute value and key
    sorted_set = sorted(set, key=lambda x: (attribute.get_value(x), x["key"]))

    print(sorted_set)


if __name__ == "__main__":
    main()
```

This Python code is a direct translation of your given Java code. It defines three classes (`LongAttribute`, `LongComparator`, and `AttributeManager`) that are similar to their counterparts in the original Java code. The `main` function demonstrates how these classes can be used together.

Please note that this code does not include all the functionality from the original Java code, such as error handling for unexpected exceptions or printing debug information.