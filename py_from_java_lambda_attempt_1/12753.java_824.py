Here's your Java interface translated into a Python class:

```Python
class DataTypeArchiveChangeManager:
    # Event types
    DOCR_CATEGORY_ADDED = 100
    DOCR_CATEGORY_REMOVED = 101
    DOCR_CATEGORY_Renamed = 102
    DOCR_CATEGORY_MOVED = 103

    DOCR_DATA_TYPE_ADDED = 104
    DOCR_DATA_TYPE_REMOVED = 105
    DOCR_DATA_TYPE_Renamed = 106
    DOCR_DATA_TYPE_MOVED = 107
    DOCR_DATA_TYPE_CHANGED = 108
    DOCR_DATA_TYPE_SETTING_CHANGED = 109
    DOCR_DATA_TYPE REPLACED = 110

    DOCR_CUSTOM_FORMAT_ADDED = 163
    DOCR_CUSTOM_FORMAT_REMOVED = 164

    def set_changed(self, type: int, old_value=None, new_value=None):
        pass

    def set_obj_changed(self, type: int, affected_object=None, old_value=None, new_value=None):
        pass
```

Note that Python does not have a direct equivalent to Java's `interface` keyword. Instead, we use the term "class" and define methods without bodies (i.e., they are abstract).