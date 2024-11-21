class AbstractDirectedLongKeyIterator:
    def __init__(self, db_long_iterator):
        self.it = db_long_iterator

    def delete(self) -> bool:
        return self.it.delete()
