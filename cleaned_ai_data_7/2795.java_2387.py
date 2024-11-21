class BackwardRecordIterator:
    def __init__(self, record_iterator):
        self.record_iterator = record_iterator

    def has_next(self):
        try:
            return self.record_iterator.has_previous()
        except Exception as e:
            print(f"An error occurred: {e}")
            return False

    def next(self):
        try:
            return self.record_iterator.previous()
        except Exception as e:
            print(f"An error occurred: {e}")
            raise StopIteration
