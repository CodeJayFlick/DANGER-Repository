Here is the equivalent Python code for the given Java code:

```Python
class SaveableColor:
    def __init__(self, color=None):
        self.color = color if color else None

    @property
    def fields(self):
        return [int, int, int]

    def save(self, obj_storage):
        if self.color is not None:
            obj_storage.putInt(self.color.getRed())
            obj_storage.putInt(self.color.getGreen())
            obj_storage.putInt(self.color.getBlue())

    def get_object_storage_fields(self):
        return self.fields

    def restore(self, obj_storage):
        red = obj_storage.getInt()
        green = obj_storage.getInt()
        blue = obj_storage.getInt()
        if red is not None and green is not None and blue is not None:
            self.color = Color(red, green, blue)

    @property
    def color(self):
        return self._color

    @color.setter
    def color(self, value):
        self._color = value

    def get_schema_version(self):
        return 0

    def is_upgradeable(self, old_schema_version):
        return False

    def upgrade(self, old_obj_storage, old_schema_version, current_obj_storage):
        return False

    def __eq__(self, other):
        if self is other:
            return True
        elif not isinstance(other, SaveableColor) or self.color != other.color:
            return False
        else:
            return True

    def __hash__(self):
        return hash(self.color)

    def __str__(self):
        return str(self.color)
```

Please note that Python does not have direct equivalent of Java's `ObjectStorage` class. So, I used the built-in data structures like lists and dictionaries to simulate its functionality.