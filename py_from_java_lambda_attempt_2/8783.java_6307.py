Here is a translation of the Java code into equivalent Python:

```Python
class VTAddressCorrelatorAdapter:
    class AddressCorrelationTableDescriptor:
        SOURCE_ENTRY_COL = {'type': 'long', 'indexed': True}
        SOURCE_ADDRESS_COL = {'type': 'long'}
        DESTINATION_ADDRESS_COL = {'type': 'long'}

        INSTANCE = None

        def __init__(self):
            self.INSTANCE = self

    TABLE_NAME = "AddressCorrelationTable"
    TABLE_SCHEMA = {}
    TABLE_INDEXES = []

    def __init__(self, db_handle):
        self.db_handle = db_handle

    @classmethod
    def create_adapter(cls, db_handle):
        return VTAddressCorrelatorAdapterV0(db_handle)

    @classmethod
    def get_adapter(cls, db_handle, monitor=None):
        if monitor is None:
            return VTAddressCorrelationAdapterV0(db_handle)
        else:
            return VTAddressCorrelationAdapterV0(db_handle, monitor)

    def create_address_record(self, source_entry_long, source_long, destination_long):
        pass  # abstract method

    def get_address_records(self, source_entry_long):
        pass  # abstract method

    def close(self):
        self.db_handle.close()

    def save(self, monitor=None):
        if monitor is None:
            self.db_handle.save("", None)
        else:
            try:
                self.db_handle.save("", None, monitor)
            except CancelledException as e:
                raise
            except Exception as e:
                raise

    def save_as(self, file, monitor=None):
        if monitor is None:
            self.db_handle.save_as(file, True)
        else:
            try:
                self.db_handle.save_as(file, True, monitor)
            except CancelledException as e:
                raise
            except Exception as e:
                raise


class VTAddressCorrelatorAdapterV0(VTAddressCorrelatorAdapter):
    def __init__(self, db_handle, monitor=None):
        super().__init__(db_handle)

    # implement abstract methods here

# Usage example:

adapter = VTAddressCorrelatorAdapter.create_adapter(db_handle)
adapter.save()
```

Please note that Python does not have direct equivalent of Java's `abstract` keyword. The translation above uses the concept of abstract classes and methods, which are achieved by defining a class with no implementation for its methods (in this case, `create_address_record`, `get_address_records`).