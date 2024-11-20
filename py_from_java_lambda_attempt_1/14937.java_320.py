Here is the translation of the Java code to Python:

```Python
class Shard:
    def __init__(self, id):
        self.id = id
        self.data_store = {}

    def store_data(self, data):
        self.data_store[data.key] = data

    def clear_data(self):
        self.data_store.clear()

    def get_data_by_id(self, id):
        return self.data_store.get(id)

    def get_id(self):
        return self.id
```

Note that Python does not have a direct equivalent to Java's `HashMap`. Instead, we can use the built-in dictionary type (`{}`) which provides similar functionality.