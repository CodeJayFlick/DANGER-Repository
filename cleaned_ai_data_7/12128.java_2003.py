class QueryRecordIterator:
    def __init__(self, iter, query):
        self.iter = iter
        self.query = query
        self.record = None
        self.forward = True

    def has_next(self):
        if self.record is None:
            if self.forward:
                self.find_next()
            else:
                self.find_previous()
        return self.record is not None

    def next(self):
        if self.has_next():
            rec = self.record
            self.record = None
            return rec
        return None

    def has_previous(self):
        if self.record is None:
            self.find_previous()
        return self.record is not None

    def previous(self):
        if self.has_previous():
            rec = self.record
            self.record = None
            return rec
        return None

    def delete(self):
        try:
            return next(iter)
        except StopIteration:
            return False


def find_next(self):
    while True:
        try:
            rec = next(self.iter)
            if self.query.matches(rec):
                self.record = rec
                break
        except StopIteration:
            pass
        except Exception as e:
            print(f"Error: {e}")


def find_previous(self):
    while True:
        try:
            rec = previous(self.iter)
            if self.query.matches(rec):
                self.record = rec
                break
        except StopIteration:
            pass
        except Exception as e:
            print(f"Error: {e}")
