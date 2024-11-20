Here is the translation of the Java code to Python:

```Python
class QueryDataSource:
    def __init__(self, seq_resources: list, unseq_resources: list):
        self.seq_resources = seq_resources
        self.unseq_resources = unseq_resources

    @property
    def seq_resources(self) -> list:
        return self._seq_resources

    @seq_resources.setter
    def seq_resources(self, value: list):
        self._seq_resources = value

    @property
    def unseq_resources(self) -> list:
        return self._unseq_resources

    @unseq_resources.setter
    def unseq_resources(self, value: list):
        self._unseq_resources = value

    @property
    def data_ttl(self) -> int:
        return self._data_ttl

    @data_ttl.setter
    def data_ttl(self, value: int):
        self._data_ttl = value

    def update_filter_using_ttl(self, filter: any) -> any:
        if self.data_ttl != 0:
            if filter is not None:
                filter = AndFilter(filter, TimeFilter.ge(System.currentTimeMillis() - self.data_ttl))
            else:
                filter = TimeFilter.ge(System.currentTimeMillis() - self.data_ttl)
        return filter
```

Note that Python does not have an exact equivalent to Java's `List` type. Instead, you can use the built-in list data structure in Python. Also, note that I used property decorators (`@property`) and setter methods to implement getter and setter methods for the attributes of the class, which is a common pattern in Python.