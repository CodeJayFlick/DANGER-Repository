class AbstractDBTracePropertyMap(T):
    def __init__(self, name: str, dbh: 'DBObject', openMode: int, lock: 'ReadWriteLock', 
                 monitor: 'TaskMonitor', baseLanguage: 'Language', trace: 'DBTrace', threadManager: 'DBThreadManager'):
        super().__init__(name, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager)

    def make_way(self, entry: tuple, span: range):
        # TODO: Would rather not rely on implementation knowledge here
        # The shape is the database record in AbstracctDBTraceAddressSnapRangePropertyMapData
        data = (entry[0],)  # Assuming 'data' is a tuple of two elements.
        self.make_way(data, span)

    def make_way(self, data: tuple, span: range):
        DBTraceUtils.make_way(data, span, lambda d, s: d.do_set_lifespan(s), 
                              lambda d: self.delete_data(d))  # Assuming 'delete_data' is a method.

    @property
    def value_class(self) -> type:
        return T

class DBTraceIntPropertyMap(AbstractDBTracePropertyMap[int]):
    pass

class DBTraceLongPropertyMap(AbstractDBTracePropertyMap[int]):
    pass

class SaveableDBFieldCodec:
    def __init__(self, object_type: 'DBObject', field: 'Field', column: int):
        super().__init__(Saveable, object_type, BinaryField, field, column)

    @staticmethod
    def encode(value: Saveable) -> bytes:
        if value is None:
            return None

        try:
            os = ByteArrayOutputStream()
            obj_storage = ObjectStorageStreamAdapter(ObjectOutputStream(os))
            value.save(obj_storage)
            return os.toByteArray()

        except IOException as e:
            raise AssertionError(e)

    @staticmethod
    def store(value: Saveable, f: BinaryField):
        f.set_binary_data(encode(value))

class DBTraceSaveablePropertyMap(AbstractDBTracePropertyMap[Saveable]):
    pass

class DBTraceStringPropertyMap(AbstractDBTracePropertyMap[str]):
    pass

class DBTraceVoidPropertyMap(AbstractDBTracePropertyMap[None]):
    pass
