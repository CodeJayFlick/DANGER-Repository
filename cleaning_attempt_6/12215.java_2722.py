class InstructHash:
    def __init__(self, inst, bl, ind):
        self.is_matched = False
        self.index = ind
        self.block = bl
        self.instruction = inst
        self.n_grams = None
        self.hash_entries = {}

    @property
    def block(self):
        return self._block

    @block.setter
    def block(self, value):
        self._block = value

    def all_unknown(self, length):
        return self.block.all_unknown(self.index, length)

    def clear_sort(self):
        self.hash_entries = {}

    def clear_ngrams(self, sz):
        self.n_grams = [None] * sz
