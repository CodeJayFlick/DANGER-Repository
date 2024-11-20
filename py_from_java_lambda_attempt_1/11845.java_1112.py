Here is the translation of the given Java code into Python:

```Python
class ProtoDBAdapterV1:
    def __init__(self, handle):
        self.table = handle.get_table("PrototypeManager.PROTO_TABLE_NAME")
        if not self.table:
            raise DatabaseVersionException("Instruction table not found")

    @property
    def version(self):
        return 1

    def get_num_records(self):
        try:
            return len(list(self.table))
        except Exception as e:
            raise IOException(str(e))

    def test_version(self, expected_version):
        if self.table is None:
            raise DatabaseVersionException("Instruction table not found")
        version_number = self.table.schema.version
        if version_number != expected_version:
            raise DatabaseVersionException(f"Prototype table: Expected Version {expected_version}, got {version_number}")

    def create_record(self, proto_id, addr, b, in_delay_slot):
        try:
            record = PrototypeManager.PROTO_SCHEMA.create_record(proto_id)
            record.binary_data = bytes(b)
            record.long_value(PrototypeManager.ADDR_COL) = addr
            record.boolean_value(2) = in_delay_slot
            self.table.put_record(record)
        except Exception as e:
            raise IOException(str(e))

    @property
    def key(self):
        return self.table.key

    def get_record(self, proto_id):
        try:
            return self.table.get_record(proto_id)
        except Exception as e:
            raise IOException(str(e))

    def get_records(self):
        try:
            return iter(self.table)
        except Exception as e:
            raise IOException(str(e))

    def delete_all(self):
        try:
            self.table.delete_all()
        except Exception as e:
            raise IOException(str(e))
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements, or the specific exception classes. The equivalent of a Java package is just the name of the module (file) in which this class resides.