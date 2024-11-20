class ProtoDBAdapter:
    def __init__(self):
        pass

    def get_record(self, proto_id: int) -> dict:
        # TO DO: implement this method to return DBRecord equivalent in Python
        raise NotImplementedError("Method not implemented")

    def get_records(self) -> iter:
        # TO DO: implement this method to return RecordIterator equivalent in Python
        raise NotImplementedError("Method not implemented")

    def get_version(self) -> int:
        # TO DO: implement this method to return the database version as an integer
        raise NotImplementedError("Method not implemented")

    def get_key(self) -> int:
        # TO DO: implement this method to return the next key as a long (or equivalent in Python)
        raise NotImplementedError("Method not implemented")

    def create_record(self, proto_id: int, addr: int, b: bytes, in_delay_slot: bool):
        # TO DO: implement this method to create a new prototype record
        raise NotImplementedError("Method not implemented")

    def get_num_records(self) -> int:
        # TO DO: implement this method to return the total number of prototypes as an integer
        raise NotImplementedError("Method not implemented")

    def delete_all(self):
        # TO DO: implement this method to delete all prototype records from the database
        raise NotImplementedError("Method not implemented")
