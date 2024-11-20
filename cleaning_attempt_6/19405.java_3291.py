class EntityData:
    def __init__(self):
        self.infos = []

    @staticmethod
    def register(data_class, name, entity_class, default_name, *code_names):
        info = EntityDataInfo(data_class, name, list(code_names), default_name, entity_class)
        for i in range(len(self.infos)):
            if isinstance(self.infos[i].c, type) and issubclass(self.infos[i].c, data_class):
                self.infos.insert(i, (EntityDataInfo,) + info.__args__)
                return
        self.infos.append(info)

    @staticmethod
    def getInfo(code_name):
        for i in self.infos:
            if i.codeName == code_name:
                return i

class EntityDataInfo(EntityData):
    def __init__(self, data_class, name, code_names, default_name, entity_class):
        super().__init__()
        self.name = name
        self.codeNames = list(code_names)
        self.defaultName = default_name
        self.entityClass = entity_class
        for i in range(len(self.codeNames)):
            if self.codeNames[i] is None:
                raise ValueError("Code names cannot be null")

    def onLanguageChange(self):
        pass

class EntityDataSerializer(serde.Serializer):
    @staticmethod
    def serialize(data: 'EntityData') -> serde.Fields:
        fields = serde.Fields()
        for key, value in data.__dict__.items():
            if isinstance(value, list) or isinstance(value, tuple):
                for item in value:
                    if hasattr(item, "serialize"):
                        fields.putObject(key + "." + str(type(item)), item.serialize())
            elif hasattr(value, "serialize"):
                fields.putObject(key, value.serialize())
        return fields

    @staticmethod
    def deserialize(data: 'EntityData', fields: serde.Fields) -> None:
        for key, value in data.__dict__.items():
            if isinstance(value, list) or isinstance(value, tuple):
                for i, item in enumerate(value):
                    if hasattr(item, "deserialize"):
                        try:
                            item.deserialize(fields.getObject(key + "." + str(type(item))))
                        except StreamCorruptedException as e:
                            raise SkriptAPIException("Invalid EntityData code name: " + key)
            elif hasattr(value, "deserialize"):
                try:
                    value.deserialize(fields.getObject(key))
                except (StreamCorruptedException, NotSerializableException) as e:
                    raise SkriptAPIException("Can't deserialize an instance of " + type(data).__name__)

    @staticmethod
    def parse(s: str) -> 'EntityData':
        for i in self.infos:
            if s.startswith(i.codeName):
                return EntityDataSerializer.deserialize(EntityData(), serde.Fields.fromObjectString(s))
        raise SkriptAPIException("Invalid entity data code name")

class SimpleLiteral(Literal):
    @staticmethod
    def parseStatic(context: 'ParseContext', exprs: List[Expression]) -> 'EntityData':
        pass

class Kleenean:
    UNKNOWN = 0
    TRUE = 1
    FALSE = 2

class EntityUtils:
    @staticmethod
    def isAgeable(entity: 'Entity') -> bool:
        return True

    @staticmethod
    def setBaby(entity: 'Entity'):
        pass

    @staticmethod
    def setAdult(entity: 'Entity'):
        pass

def main():
    data = EntityData()
    data.register(Player, "player", Player.class)
    print(data.getInfo("player"))

if __name__ == "__main__":
    main()

