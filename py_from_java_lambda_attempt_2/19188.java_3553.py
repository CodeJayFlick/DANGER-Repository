Here is a translation of the provided Java code into equivalent Python:

```Python
class ConfigurationSerializer:
    def __init__(self):
        pass

    def serialize(self, o: 'ConfigurationSerializable') -> dict:
        serialized = {'value': self.serialize_cs(o)}
        return serialized

    def must_sync_deserialization(self) -> bool:
        return False

    def can_be_instantiated(self) -> bool:
        return False

    def deserialize(self, fields: dict) -> 'ConfigurationSerializable':
        value = fields.get('value')
        if not isinstance(value, str):
            raise StreamCorruptedException()
        info = self.info
        assert info is not None
        t = self.deserialize_cs(value, info['c'])
        if t is None:
            raise StreamCorruptedException()
        return t

    @staticmethod
    def serialize_cs(o: 'ConfigurationSerializable') -> str:
        yml_config = YamlConfiguration()
        yml_config.set('value', o)
        return yml_config.saveToString()

    @staticmethod
    def deserialize_cs(s: str, c) -> 'ConfigurationSerializable':
        try:
            yaml_config = YamlConfiguration.loadFromString(s)
        except InvalidConfigurationException as e:
            return None

        value = yaml_config.get('value')
        if not isinstance(value, type(c)):
            return None
        return value

    def new_instance(self, c: type) -> 'ConfigurationSerializable':
        assert False
        return None

    @staticmethod
    def deserialize(s: str):
        info = ConfigurationSerializer.info
        assert info is not None
        return ConfigurationSerializer.deserialize_cs_old(s, info['c'])

    @staticmethod
    def deserialize_cs_old(s: str, c) -> 'ConfigurationSerializable':
        try:
            yaml_config = YamlConfiguration.loadFromString(s.replace('\uFEFF', '\n'))
        except InvalidConfigurationException as e:
            return None

        value = yaml_config.get('value')
        if not isinstance(value, type(c)):
            return None
        return value


class YamlConfiguration:
    def saveToString(self) -> str:
        pass  # implement this method

    @staticmethod
    def loadFromString(s: str):
        pass  # implement this method


# You would need to define the following variables and methods in your Python code.
ConfigurationSerializer.info = None
```

Please note that I've not implemented all the Java classes (like `Fields`, `StreamCorruptedException`) as they are not necessary for translation. Also, some parts of the original code might be specific to a certain framework or library which is not available in Python.