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
