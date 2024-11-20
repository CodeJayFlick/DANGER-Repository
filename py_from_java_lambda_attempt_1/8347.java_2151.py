Here is the translation of the given Java code into Python:

```Python
class AbstractFriendClassMsType:
    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.friend_class_record_number = None  # Assuming this should be a RecordNumber type in Python

    def emit(self, builder, bind):
        # TODO: API not documented. Fix this as figured out.
        builder.append("friend:")
        if self.pdb and self.friend_class_record_number:
            builder.append(str(self.pdb.get_type_record(self.friend_class_record_number)))
```

Note that I have made the following assumptions:

- `RecordNumber` is a Python class or type, which can be used to represent record numbers.
- The methods `get_type_record()` and `toString()` are available on the `pdb` object.