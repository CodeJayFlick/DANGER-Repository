Here is the translation of the Java code into Python:

```Python
class PlateFieldLocation:
    def __init__(self):
        pass

    def __str__(self):
        return super().__str__() + ", Comment Row = " + str(self.comment_row)

    def __eq__(self, other):
        if isinstance(other, PlateFieldLocation) and self.__dict == other.__dict:
            return True
        else:
            return False

    @property
    def comment_row(self):
        return self._comment_row

    @comment_row.setter
    def comment_row(self, value):
        self._comment_row = value

class SaveState:
    def __init__(self):
        pass

    def put_int(self, key, value):
        pass  # implement this method as needed

    def get_int(self, key, default_value=0):
        return default_value  # implement this method as needed
```

Note that the Python code does not exactly replicate the Java code. The `SaveState` class is a placeholder and needs to be implemented according to your specific requirements.