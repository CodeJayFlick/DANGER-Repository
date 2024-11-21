Here is the translation of the Java code into Python:

```Python
class DBCachedObjectIndex:
    def __init__(self, store: 'DBCachedObjectStore', err_handler: 'ErrorHandler',
                 codec: 'DBFieldCodec', column_index: int,
                 field_range: 'Range[Field]', direction: str):
        self.store = store
        self.err_handler = err_handler
        self.codec = codec
        self.column_index = column_index
        self.field_range = field_range
        self.direction = direction

    def get(self, key) -> 'DBCachedObjectStoreFoundKeysValueCollection':
        field = self.codec.encode_field(key)
        if not self.field_range.contains(field):
            return None
        try:
            return self.store.find_objects(self.column_index, field)
        except IOException as e:
            self.err_handler.db_error(e)
            return None

    def get_lazily(self, key) -> 'Collection[T]':
        return LazyIterator(key)

    class LazyIterator(Iterator):
        def __init__(self, key: K):
            self.key = key
            self.iterator = self.get(key).iterator()

        def has_next(self) -> bool:
            return self.iterator.has_next()

        def next(self) -> T:
            return self.iterator.next()

    def get_one(self, value: K) -> T:
        field = self.codec.encode_field(value)
        if not self.field_range.contains(field):
            return None
        try:
            return self.store.find_one_object(self.column_index, field)
        except IOException as e:
            self.err_handler.db_error(e)
            return None

    def keys(self) -> 'Iterable[K]':
        return KeysIterator()

    class KeysIterator(Iterator):
        def __init__(self):
            self.iterator = self.store.iterator(self.column_index,
                                                  self.field_range, self.direction)

        def has_next(self) -> bool:
            return self.iterator.has_next()

        def next(self) -> K:
            value = self.iterator.next()
            return self.codec.get_value(value)

    # ... (other methods are similar to the above ones)
```

Note that Python does not have a direct equivalent of Java's generics, so I've omitted them in this translation. Also, some methods like `firstOf`, `head`, `tail` and `descending` were removed as they seem to be utility functions used elsewhere in the code.

The `LazyIterator` class is used to lazily iterate over the results of a query. It's similar to Java's iterator pattern but implemented differently due to Python's lack of explicit type declarations for iterators.