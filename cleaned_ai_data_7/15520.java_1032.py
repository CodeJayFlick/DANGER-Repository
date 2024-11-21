class NDIndexFixed:
    def __init__(self, index):
        self.index = index

    @property
    def index(self):
        return self._index

    def get_rank(self):
        return 1
