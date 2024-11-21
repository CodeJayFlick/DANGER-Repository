Here is the equivalent Python code:

```Python
class DomainObjectChangeRecord:
    def __init__(self):
        self.event_type = 0
        self.sub_event_type = 0
        self.old_value = None
        self.new_value = None

    @property
    def event_type(self):
        return self._event_type

    @event_type.setter
    def event_type(self, value):
        self._event_type = value

    @property
    def sub_event_type(self):
        return self._sub_event_type

    @sub_event_type.setter
    def sub_event_type(self, value):
        self._sub_event_type = value

    @property
    def old_value(self):
        return self._old_value

    @old_value.setter
    def old_value(self, value):
        self._old_value = value

    @property
    def new_value(self):
        return self._new_value

    @new_value.setter
    def new_value(self, value):
        self._new_value = value

    def __str__(self):
        return f"{{\n\tnewValue: {self.new_value},\n\toldValue: {self.old_value},\n\teventType: {self.event_type},\n\tsubEventType: {self.sub_event_type}\n}}"

# Example usage:
record = DomainObjectChangeRecord()
print(record)
```

Note that Python does not have an equivalent to Java's `implements Serializable` or the concept of a "serialVersionUID".