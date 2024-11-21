Here is the translation of the given Java code into Python:

```Python
class CompositeViewerDataTypeManager:
    def __init__(self, root_name: str, composite):
        super().__init__(root_name, composite.data_type_manager().data_organization)
        self.transaction_id = start_transaction("")
        self.original_dtm = composite.data_type_manager()
        self.universal_id = original_dtm.get_universal_id()  # mimic original DTM
        super().resolve(composite, None)

    def close(self):
        end_transaction(self.transaction_id, True)
        super().close()

    def get_type(self) -> 'ArchiveType':
        return self.original_dtm.type

def start_transaction(transaction_name: str) -> int:
    # Implement this function as per your requirement
    pass

class ArchiveType:
    # Implement this class as per your requirement
    pass
```

Please note that Python does not have direct equivalent of Java's `package`, so I did not include any package declaration in the above code. Also, some methods like `getDataTypeManager()`, `getDataOrganization()` and `getType()` are assumed to be part of a class called `Composite` which is also missing from this translation as it was not provided with you.