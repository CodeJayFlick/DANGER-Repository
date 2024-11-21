Here is the translation of the Java code into equivalent Python:

```Python
class DataTypeManagerChangeListenerAdapter:
    def category_added(self, dtm: 'DataTypeManager', path: 'CategoryPath') -> None:
        pass

    def category_moved(self, dtm: 'DataTypeManager', old_path: 'CategoryPath', new_path: 'CategoryPath') -> None:
        pass

    def category_removed(self, dtm: 'DataTypeManager', path: 'CategoryPath') -> None:
        pass

    def category_renamed(self, dtm: 'DataTypeManager', old_path: 'CategoryPath', new_path: 'CategoryPath') -> None:
        pass

    def data_type_added(self, dtm: 'DataTypeManager', path: 'DataTypePath') -> None:
        pass

    def data_type_changed(self, dtm: 'DataTypeManager', path: 'DataTypePath') -> None:
        pass

    def data_type_moved(self, dtm: 'DataTypeManager', old_path: 'DataTypePath', new_path: 'DataTypePath') -> None:
        pass

    def data_type_removed(self, dtm: 'DataTypeManager', path: 'DataTypePath') -> None:
        pass

    def data_type_renamed(self, dtm: 'DataTypeManager', old_path: 'DataTypePath', new_path: 'DataTypePath') -> None:
        pass

    def data_type_replaced(self, dtm: 'DataTypeManager', old_path: 'DataTypePath', new_path: 'DataTypePath', 
                           new_data_type: 'DataType') -> None:
        pass

    def favorites_changed(self, dtm: 'DataTypeManager', path: 'DataTypePath', is_favorite: bool) -> None:
        pass

    def source_archive_added(self, dtm: 'DataTypeManager', data_type_source: 'SourceArchive') -> None:
        pass

    def source_archive_changed(self, dtm: 'DataTypeManager', data_type_source: 'SourceArchive') -> None:
        pass
```

Note that Python does not have direct equivalent of Java's interfaces and abstract classes. The above code is a simple translation where each method in the adapter class has been translated into an equivalent function in Python.