Here is a translation of the given code in Python:

```python
class AddressRangeMapDB:
    def __init__(self):
        self.modCount = 0
        self.valueField = LongField.INSTANCE
        self.rangeMapTable = None
        self.lastStart = None
        self.lastEnd = None

    class RangeIterator:
        def __init__(self, value):
            self.hasNext()
            self.next()

    class ValueRangeIterator:
        def __init__(self):
            self.modCount = 0
            self.valueField = LongField.INSTANCE
            self.rangeMapTable = None