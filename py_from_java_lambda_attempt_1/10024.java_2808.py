Here is the translation of the Java code into Python:

```Python
class TestDataKeyModel:
    ROWCOUNT = 12
    
    BYTE_COL = 0
    SHORT_COL = 1
    INT_COL = 2
    LONG_COL = 3
    FLOAT_COL = 4
    DOUBLE_COL = 5
    STRING_COL = 6

    def __init__(self):
        self.bytes = [bytearray([9]), bytearray([3]), bytearray([12]), bytearray([55]), bytearray([0]), bytearray([223]), bytearray([255]), bytearray([3]), bytearray([16]), bytearray([2]), bytearray([3]), bytearray([4])]
        self.shorts = [(841), (3077), (3130), (8463), (2976), (1799), (3146), (4625), (8911), (9665), (9666), (9667)]
        self.ints = [49279, 161497, 14971, 29299E, 42801, 98741, 12747, 61987, 13511, 73954, 739542, 739543]
        self.longs = [(0x0000000DFAA00C4L), (1<<63-2**32+1), (4294967295), (4446143), (56961780), (685526E5DL), (9A1FD98EL), (44AD2B1869L), (2928E64CL), (71CE1DDB2L), (71CE1DDB3L), (71CE1DDB4L)]
        self.floats = [(0.14311124), (0.08409768), (0.55121480), (0.31038480), (0.73800564), (0.91332513), (0.01602411), (0.23380074), (0.09268288), (0.9522519), (0.952251901), (0.952251902)]
        self.doubles = [(0.50554326393620910), (0.13198657566384920), (0.64075103656548560), (0.02537676611361095), (0.90734608401968010), (0.28502871389575400), (0.13398664627861856), (0.12874345736088588), (0.40378684558854416), (0.77268978814256020), (0.77268978814256021), (0.77268978814256022)]
        self.strings = ["one", "two", "THREE", "Four", "FiVe", "sIx", "SeVEn", "EighT", "NINE", "ten", "ten", "ten"]
        
    def createIncrementalLoadJob(self):
        load_job = IncrementalLoadJob(self, IncrementalLoadJobListener())
        return load_job

    def getCurrentLoadJob(self):
        return self.load_job

    def setDelayTimeBetweenAddingDataItemsWhileLoading(self, millis):
        self.time_between_adding_data_items_millis = millis

    def getDelayTimeBetweenAddingDataItemsWhileLoading(self):
        return self.time_between_adding_data_items_millis

    def getTestRowCount(self):
        return self.ROWCOUNT

    def doLoad(self, accumulator, monitor):
        for i in range(self.ROWCOUNT):
            if monitor.checkCanceled():
                break
            accumulator.add(i)
            time.sleep(self.time_between_adding_data_items_millis)

    class ByteTableColumn:
        def getColumnName(self):
            return "Byte"

        def getValue(self, row_object, settings, provider):
            long_as_int = int(row_object)
            if long_as_int < 0 or long_as_int >= len(self.bytes):
                # must be using a model that adds more data than the default; fabricate a result
                return bytes([int(time.time())])[0]
            return self.bytes[long_as_int]

    class ShortTableColumn:
        def getColumnName(self):
            return "Short"

        def getValue(self, row_object, settings, provider):
            long_as_int = int(row_object)
            if long_as_int < 0 or long_as_int >= len(self.shorts):
                # must be using a model that adds more data than the default; fabricate a result
                return short(int(time.time()))
            return self.shorts[long_as_int]

    class IntegerTableColumn:
        def getColumnName(self):
            return "Integer"

        def getValue(self, row_object, settings, provider):
            long_as_int = int(row_object)
            if long_as_int < 0 or long_as_int >= len(self.ints):
                # must be using a model that adds more data than the default; fabricate a result
                return int(time.time())
            return self.ints[long_as_int]

    class LongTableColumn:
        def getColumnName(self):
            return "Long"

        def getValue(self, row_object, settings, provider):
            long_as_int = int(row_object)
            if long_as_int < 0 or long_as_int >= len(self.longs):
                # must be using a model that adds more data than the default; fabricate a result
                return time.time()
            return self.longs[long_as_int]

    class FloatTableColumn:
        def getColumnName(self):
            return "Float"

        def getValue(self, row_object, settings, provider):
            long_as_int = int(row_object)
            if long_as_int < 0 or long_as_int >= len(self.floats):
                # must be using a model that adds more data than the default; fabricate a result
                return float(time.time())
            return self.floats[long_as_int]

    class DoubleTableColumn:
        def getColumnName(self):
            return "Double"

        def getValue(self, row_object, settings, provider):
            long_as_int = int(row_object)
            if long_as_int < 0 or long_as_int >= len(self.doubles):
                # must be using a model that adds more data than the default; fabricate a result
                return float(time.time())
            return self.doubles[long_as_int]

    class StringTableColumn:
        def getColumnName(self):
            return "String"

        def getValue(self, row_object, settings, provider):
            long_as_int = int(row_object)
            if long_as_int < 0 or long_as_int >= len(self.strings):
                # must be using a model that adds more data than the default; fabricate a result
                return str(time.time())
            return self.strings[long_as_int]

    def createTableColumnDescriptor(self):
        descriptor = TableColumnDescriptor()
        
        descriptor.addVisibleColumn(ByteTableColumn())
        descriptor.addVisibleColumn(ShortTableColumn())
        descriptor.addVisibleColumn(IntegerTableColumn())
        descriptor.addVisibleColumn(LongTableColumn())
        descriptor.addVisibleColumn(FloatTableColumn())
        descriptor.addVisibleColumn(DoubleTableColumn())
        descriptor.addVisibleColumn(StringTableColumn())

        return descriptor

    def __str__(self):
        return "TestDataKeyModel"
```

Please note that Python does not have direct equivalent of Java's `Thread.sleep()` method. Instead, you can use the built-in `time` module to achieve similar functionality.

Also, this code assumes that there are classes like `IncrementalLoadJob`, `Accumulator`, and `TaskMonitor` which were present in the original Java code but not provided here. You would need to implement these yourself or find a Python equivalent if you want to use them.