class AbstractFriendClassMsType:
    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.friend_class_record_number = None  # Assuming this should be a RecordNumber type in Python

    def emit(self, builder, bind):
        # TODO: API not documented. Fix this as figured out.
        builder.append("friend:")
        if self.pdb and self.friend_class_record_number:
            builder.append(str(self.pdb.get_type_record(self.friend_class_record_number)))
