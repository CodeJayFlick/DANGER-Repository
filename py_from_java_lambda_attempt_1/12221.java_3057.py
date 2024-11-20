Here is your Java code translated into Python:

```Python
class AbstractIntegerDataType:
    def __init__(self, name, signed):
        self.signed = signed

    @staticmethod
    def getSignedTypes():
        if not hasattr(AbstractIntegerDataType, 'signed_types'):
            AbstractIntegerDataType.signed_types = [SignedByteDataType(), SignedWordDataType(),
                                                      Integer3DataType(), SignedDWordDataType(),
                                                      Integer5DataType(), Integer6DataType(), Integer7DataType(),
                                                      SignedQWordDataType()]
        return AbstractIntegerDataType.signed_types

    @staticmethod
    def getUnsignedTypes():
        if not hasattr(AbstractIntegerDataType, 'unsigned_types'):
            AbstractIntegerDataType.unsigned_types = [ByteDataType(), WordDataType(),
                                                       UnsignedInteger3DataType(), DWordDataType(),
                                                       UnsignedInteger5DataType(), UnsignedInteger6DataType(),
                                                       UnsignedInteger7DataType(), QWordDataType()]
        return AbstractIntegerDataType.unsigned_types

    @staticmethod
    def getSignedDataType(size, dtm=None):
        if size < 1:
            return DefaultDataType()
        elif size == 16:
            return Integer16DataType().clone(dtm)
        elif size > 8 and not dtm:
            return new ArrayDataType(SignedByteDataType(), size, 1)
        else:
            data_types = AbstractIntegerDataType.getSignedTypes()
            if dmt:
                data_organization = dmt.data_organization
                index = data_organization.long_long_size - 1
                if index >= 0 and index < 8:
                    return SignedLongLongDataType().clone(dtm)
                elif size == data_organization.integer_size:
                    return IntegerDataType().clone(dtm)
                elif size == data_organization.short_size:
                    return ShortDataType().clone(dtm)
            return data_types[size - 1]

    @staticmethod
    def getUnsignedDataType(size, dtm=None):
        if size < 1:
            return DefaultDataType()
        elif size == 16:
            return UnsignedInteger16DataType()
        elif size > 8 and not dtm:
            return Undefined.getUndefinedDataType(size)
        else:
            data_types = AbstractIntegerDataType.getUnsignedTypes()
            if dmt:
                data_organization = dmt.data_organization
                index = data_organization.long_long_size - 1
                if index >= 0 and index < 8:
                    return UnsignedLongLongDataType().clone(dtm)
                elif size == data_organization.integer_size:
                    return UnsignedIntegerDataType().clone(dtm)
                elif size == data_organization.short_size:
                    return UnsignedShortDataType().clone(dtm)
            return data_types[size - 1]

class DefaultDataType:
    pass

class SignedByteDataType:
    def clone(self, dtm):
        return self

class ByteDataType:
    pass

class WordDataType:
    pass

class DWordDataType:
    pass

class QWordDataType:
    pass

class Integer3DataType:
    def clone(self, dtm):
        return self

class Integer5DataType:
    def clone(self, dtm):
        return self

class Integer6DataType:
    def clone(self, dtm):
        return self

class Integer7DataType:
    def clone(self, dtm):
        return self

class SignedQWordDataType:
    pass

class UnsignedInteger3DataType:
    pass

class UnsignedInteger5DataType:
    pass

class UnsignedInteger6DataType:
    pass

class UnsignedInteger7DataType:
    pass
```

Please note that this is a direct translation of your Java code into Python. It might not be the most idiomatic or efficient way to write Python, but it should work as expected.