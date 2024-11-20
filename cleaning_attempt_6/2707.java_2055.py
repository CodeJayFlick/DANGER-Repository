import itertools

class CatenatedCollection:
    def __init__(self, collections):
        self.collections = collections

    @staticmethod
    def concatenate(collections):
        return itertools.chain(*[c for c in collections])

    def iterator(self):
        return iter(CatenatedCollection.concatenate(self.collections))
