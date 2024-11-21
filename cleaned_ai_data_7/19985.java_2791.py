class EmptyIterable:
    instance = None

    def __new__(cls):
        if cls.instance is None:
            cls.instance = object.__new__(cls)
        return cls.instance

    @staticmethod
    def get():
        return EmptyIterable()

    def iterator(self):
        from ch.njol.util.coll.iterator import EmptyIterator
        return EmptyIterator.get()

    def __eq__(self, other):
        if isinstance(other, type) and issubclass(other, EmptyIterable):
            return True
        return False

    def __hash__(self):
        return 0
