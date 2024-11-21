Here is the equivalent Python code:

```Python
class ShowDevicesResult:
    def __init__(self):
        pass

    def __init__(self, name=None, sg_name=None):
        self.name = name
        self.sg_name = sg_name

    @classmethod
    def deserialize(cls, buffer):
        result = cls()
        if buffer is not None and len(buffer) > 0:
            result.name = buffer.decode('utf-8').split(',')[0].strip().replace("'", "")
            result.sg_name = buffer.decode('utf-8').split(',')[1].strip().replace("'", "")
        return result

    def serialize(self):
        serialized_data = f"'{self.name}'" + ',' + f"'{self.sg_name}'"
        return serialized_data.encode('utf-8')

    def __str__(self):
        return "ShowDevicesResult{" + f" name='{self.name}'", f", sgName='{self.sg_name}'" + "}"

    def __eq__(self, other):
        if self is other:
            return True
        elif isinstance(other, ShowDevicesResult) and self.__dict__ == other.__dict__':
            return True
        else:
            return False

    def __hash__(self):
        return hash((self.name, self.sg_name))
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation.