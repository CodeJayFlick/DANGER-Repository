Here is the translation of the given Java code into Python:

```Python
class InstanceSettingsDBAdapterV0:
    V0_INST_ADDR_COL = 0
    V0_INST_NAME_COL = 1
    V0_INST_LONG_VALUE_COL = 2
    V0_INST_STRING_VALUE_COL = 3
    V0_INST_BYTE_VALUE_COL = 4

    V0_INSTANCE_SCHEMA = {
        "Settings ID": {"type": "long"},
        "Address": {"type": "string"},
        "Settings Name": {"type": "string"},
        "Long Value": {"type": "long"},
        "String Value": {"type": "string"},
        "Byte Value": {"type": "bytes"}
    }

    def __init__(self, handle, create=False):
        if create:
            self.instance_table = handle.create_table("InstanceSettings", V0_INSTANCE_SCHEMA)
        else:
            try:
                self.instance_table = handle.get_table("InstanceSettings")
            except KeyError as e:
                raise VersionException(f"Missing Table: {e}")
            if not self.instance_table or self.instance_table.schema["version"] != 0:
                raise VersionException(
                    f"Expected version 0 for table 'InstanceSettings' but got {self.instance_table.schema['version']}")

    def create_instance_record(self, addr, name, str_value, long_value, byte_value):
        record = {"Address": addr, "Settings Name": name}
        if str_value:
            record["String Value"] = str_value
        else:
            record.pop("String Value", None)
        if long_value is not None:
            record["Long Value"] = long_value
        else:
            record.pop("Long Value", None)
        if byte_value:
            record["Byte Value"] = byte_value
        else:
            record.pop("Byte Value", None)

        self.instance_table.put_record(record)
        return record

    def get_instance_keys(self, addr):
        try:
            records = self.instance_table.find_records({"Address": addr})
            return [record for record in records]
        except KeyError as e:
            raise IOException(f"Failed to find instance with address {e}")

    def remove_instance_record(self, settings_id):
        if not self.instance_table.delete(settings_id):
            return False
        else:
            return True

    def get_instance_record(self, settings_id):
        try:
            record = self.instance_table.get(settings_id)
            return record
        except KeyError as e:
            raise IOException(f"Failed to find instance with id {e}")

    def update_instance_record(self, record):
        if not self.instance_table.put(record):
            return False
        else:
            return True

    def get_records(self, start=None, end=None):
        try:
            records = []
            for row in self.instance_table.iterate():
                if (start is None or int(row["Address"]) >= start) and \
                   (end is None or int(row["Address"]) <= end):
                    records.append(row)
            return [record for record in records]
        except KeyError as e:
            raise IOException(f"Failed to iterate over instances with address {e}")

    def get_all_records(self):
        try:
            return list(self.instance_table.iterate())
        except Exception as e:
            raise IOException(f"Failed to retrieve all instance records: {str(e)}")

    def count_instances(self):
        return self.instance_table.count()

    def delete_instances(self, start=None, end=None, monitor=None):
        if not isinstance(monitor, TaskMonitor) and monitor is not None:
            raise TypeError("Invalid task monitor")
        
        try:
            for row in self.instance_table.iterate():
                addr = int(row["Address"])
                if (start is None or addr >= start) and \
                   (end is None or addr <= end):
                    self.instance_table.delete(addr)
        except Exception as e:
            raise CancelledException(f"Failed to delete instances: {str(e)}")
```

Please note that Python does not have direct equivalent of Java's DBHandle, Schema, Table, Field, RecordIterator and other classes. The above code is a simplified version of the given Java code in terms of database operations.