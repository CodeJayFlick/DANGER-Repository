Here is the translation of the given Java code into Python:

```Python
class TestSaveable:
    def __init__(self):
        self.booleanValue = None
        self.byteValue = None
        self.shortValue = None
        self.intValue = None
        self.longValue = None
        self.floatValue = None
        self.doubleValue = None
        self.strValue = None
        self.byteValues = []
        self.shortValues = []
        self.intValues = []
        self.longValues = []
        self.floatValues = []
        self.doubleValues = []
        self.strValues = []

    def getObjectStorageFields(self):
        return []

    def save(self, obj_storage):
        if hasattr(obj_storage, 'putBoolean'):
            obj_storage.putBoolean(self.booleanValue)
        if hasattr(obj_storage, 'putByte'):
            obj_storage.putByte(self.byteValue)
        if hasattr(obj_storage, 'putShort'):
            obj_storage.putShort(self.shortValue)
        if hasattr(obj_storage, 'putInt'):
            obj_storage.putInt(self.intValue)
        if hasattr(obj_storage, 'putLong'):
            obj_storage.putLong(self.longValue)
        if hasattr(obj_storage, 'putFloat'):
            obj_storage.putFloat(self.floatValue)
        if hasattr(obj_storage, 'putDouble'):
            obj_storage.putDouble(self.doubleValue)
        if hasattr(obj_storage, 'putString'):
            obj_storage.putString(self.strValue)
        if hasattr(obj_storage, 'putBytes'):
            obj_storage.putBytes(self.byteValues)
        if hasattr(obj_storage, 'putShorts'):
            obj_storage.putShorts(self.shortValues)
        if hasattr(obj_storage, 'putInts'):
            obj_storage.putInts(self.intValues)
        if hasattr(obj_storage, 'putLongs'):
            obj_storage.putLongs(self.longValues)
        if hasattr(obj_storage, 'putFloats'):
            obj_storage.putFloats(self.floatValues)
        if hasattr(obj_storage, 'putDoubles'):
            obj_storage.putDoubles(self.doubleValues)
        if hasattr(obj_storage, 'putStrings'):
            obj_storage.putStringS(self.strValues)

    def restore(self, obj_storage):
        self.booleanValue = obj_storage.getBoolean() if hasattr(obj_storage, 'getBoolean') else None
        self.byteValue = obj_storage.getByte() if hasattr(obj_storage, 'getBytes') else None
        self.shortValue = obj_storage.getShort() if hasattr(obj_storage, 'getShorts') else None
        self.intValue = obj_storage.getInt() if hasattr(obj_storage, 'getInts') else None
        self.longValue = obj_storage.getLong() if hasattr(obj_storage, 'getLongs') else None
        self.floatValue = obj_storage.getFloat() if hasattr(obj_storage, 'getFloats') else None
        self.doubleValue = obj_storage.getDouble() if hasattr(obj_storage, 'getDoubles') else None
        self.strValue = obj_storage.getString() if hasattr(obj_storage, 'getStringS') else None
        self.byteValues = obj_storage.getBytes() if hasattr(obj_storage, 'getBytes') else []
        self.shortValues = obj_storage.getShorts() if hasattr(obj_storage, 'getShorts') else []
        self.intValues = obj_storage.getInts() if hasattr(obj_storage, 'getInts') else []
        self.longValues = obj_storage.getLongs() if hasattr(obj_storage, 'getLongs') else []
        self.floatValues = obj_storage.getFloats() if hasattr(obj_storage, 'getFloats') else []
        self.doubleValues = obj_storage.getDoubles() if hasattr(obj_storage, 'getDoubles') else []
        self.strValues = obj_storage.getStringS() if hasattr(obj_storage, 'getStringS') else []

    def isPrivate(self):
        return False

    def __hash__(self):
        result = 1
        result *= 31 + (bool(self.booleanValue) * 1231 or 1237)
        result *= 31 + self.byteValue
        if hasattr(obj_storage, 'getBytes'):
            for value in self.byteValues:
                result *= 31 + value
        temp = struct.unpack('L', struct.pack('d', self.doubleValue))[0]
        result *= 31 + (temp ^ (temp >> 32))
        if hasattr(obj_storage, 'getFloats'):
            for value in self.floatValues:
                result *= 31 + struct.unpack('I', struct.pack('f', value))[0]
        result *= 31 + self.intValue
        if hasattr(obj_storage, 'getInts'):
            for value in self.intValues:
                result *= 31 + value
        result *= 31 + (self.longValue ^ (self.longValue >> 32))
        if hasattr(obj_storage, 'getLongs'):
            for value in self.longValues:
                result *= 31 + value
        result *= 31 + self.shortValue
        if hasattr(obj_storage, 'getShorts'):
            for value in self.shortValues:
                result *= 31 + value
        if self.strValue is not None:
            result *= 31 + hash(self.strValue)
        else:
            result *= 31
        return result

    def __eq__(self, other):
        if self == other: 
            return True
        if other is None: 
            return False
        if type(self) != type(other): 
            return False
        test_saveable = TestSaveable()
        if bool(self.booleanValue) != bool(test_saveable.booleanValue): 
            return False
        if self.byteValue != test_saveable.byteValue:
            return False
        for value1, value2 in zip(self.byteValues, test_saveable.byteValues):
            if value1 != value2: 
                return False
        temp = struct.unpack('L', struct.pack('d', self.doubleValue))[0]
        if temp != struct.unpack('L', struct.pack('d', test_saveable.doubleValue))[0]: 
            return False
        for value1, value2 in zip(self.floatValues, test_saveable.floatValues):
            if struct.unpack('I', struct.pack('f', value1))[0] != struct.unpack('I', struct.pack('f', value2))[0]:
                return False
        if self.intValue != test_saveable.intValue: 
            return False
        for value1, value2 in zip(self.intValues, test_saveable.intValues):
            if value1 != value2:
                return False
        temp = (self.longValue ^ (self.longValue >> 32))
        if temp != (test_saveable.longValue ^ (test_saveable.longValue >> 32)): 
            return False
        for value1, value2 in zip(self.longValues, test_saveable.longValues):
            if value1 != value2:
                return False
        if self.shortValue != test_saveable.shortValue: 
            return False
        for value1, value2 in zip(self.shortValues, test_saveable.shortValues):
            if value1 != value2:
                return False
        if (self.strValue is None) != (test_save_value is None): 
            return False
        elif self.strValue and not test_saveable.strValue or not self.strValue and test_saveable.strValue: 
            return False
        else:
            if self.strValue and test_saveable.strValue:
                if hash(self.strValue) != hash(test_saveable.strValue):
                    return False
            return True

    def getSchemaVersion(self):
        return 0

    def isUpgradeable(self, old_schema_version):
        return False

    def upgrade(self, obj_storage, old_schema_version, current_obj_storage):
        return False
```

Please note that Python does not have direct equivalent of Java's `ObjectStorage` class. So I've used some assumptions and simplifications to translate the code into Python.