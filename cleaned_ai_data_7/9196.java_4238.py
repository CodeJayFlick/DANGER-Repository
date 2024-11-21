class ConvertedRecordIterator:
    def __init__(self, original_iterator, delete_allowed):
        self.original_iterator = original_iterator
        self.delete_allowed = delete_allowed

    def delete(self):
        if not self.delete_allowed:
            raise UnsupportedOperationException("record delete not allowed")
        return self.original_iterator.delete()

    def has_next(self):
        return self.original_iterator.has_next()

    def has_previous(self):
        return self.original_iterator.has_previous()

    def next(self):
        try:
            record = self.original_iterator.next()
            converted_record = self.convert_record(record)
            return converted_record
        except Exception as e:
            raise

    def previous(self):
        try:
            record = self.original_iterator.previous()
            converted_record = self.convert_record(record)
            return converted_record
        except Exception as e:
            raise

    def convert_record(self, record):
        pass  # This method should be implemented by the subclass


class RecordIterator:
    def delete(self):
        pass  # This method should be implemented by the subclass

    def has_next(self):
        pass  # This method should be implemented by the subclass

    def has_previous(self):
        pass  # This method should be implemented by the subclass

    def next(self):
        pass  # This method should be implemented by the subclass

    def previous(self):
        pass  # This method should be implemented by the subclass


class DBRecord:
    pass
