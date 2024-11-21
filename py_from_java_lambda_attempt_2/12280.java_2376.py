Here is the translation of the Java interface into a Python class:

```Python
class DataTypeManagerChangeListener:
    def category_added(self, dtm: 'DataTypeManager', path: 'CategoryPath'):
        pass  # Implement your logic here

    def category_removed(self, dtm: 'DataTypeManager', path: 'CategoryPath'):
        pass  # Implement your logic here

    def category_renamed(self, dtm: 'DataTypeManager', old_path: 'CategoryPath', new_path: 'CategoryPath'):
        pass  # Implement your logic here

    def category_moved(self, dtm: 'DataTypeManager', old_path: 'CategoryPath', new_path: 'CategoryPath'):
        pass  # Implement your logic here

    def data_type_added(self, dtm: 'DataTypeManager', path: 'DataTypePath'):
        pass  # Implement your logic here

    def data_type_removed(self, dtm: 'DataTypeManager', path: 'DataTypePath'):
        pass  # Implement your logic here

    def data_type_renamed(self, dtm: 'DataTypeManager', old_path: 'DataTypePath', new_path: 'DataTypePath'):
        pass  # Implement your logic here

    def data_type_moved(self, dtm: 'DataTypeManager', old_path: 'DataTypePath', new_path: 'DataTypePath'):
        pass  # Implement your logic here

    def data_type_changed(self, dtm: 'DataTypeManager', path: 'DataTypePath'):
        pass  # Implement your logic here

    def data_type_replaced(self, dtm: 'DataTypeManager', old_path: 'DataTypePath', new_path: 'DataTypePath', 
                           new_data_type: 'DataType'):
        pass  # Implement your logic here

    def favorites_changed(self, dtm: 'DataTypeManager', path: 'DataTypePath', is_favorite: bool):
        pass  # Implement your logic here

    def source_archive_changed(self, dtm: 'DataTypeManager', source_archive: 'SourceArchive'):
        pass  # Implement your logic here

    def source_archive_added(self, dtm: 'DataTypeManager', source_archive: 'SourceArchive'):
        pass  # Implement your logic here
```

Note that in Python, we don't have a direct equivalent of Java's interfaces. Instead, you can use abstract base classes (ABCs) or just define the methods as above without any implementation.