class MultiComparableArrayIterator:
    def __init__(self, arrays, forward=True):
        self.arrays = arrays
        self.forward = forward
        self.comps = [None] * len(arrays)
        self.indices = [len(array) - 1 for array in arrays]

    def hasNext(self):
        for i in range(len(self.arrays)):
            if self.indices[i] >= 0 and self.indices[i] < len(self.arrays[i]):
                return True
        return False

    def next(self):
        comps = [None] * len(self.arrays)
        for i in range(len(self.arrays)):
            if self.comps[i] is None:
                if self.indices[i] >= 0 and self.indices[i] < len(self.arrays[i]):
                    self.comps[i] = self.arrays[i][self.indices[i]]
            else:
                next_comp = self.comps[i]
                for j in range(len(self.arrays)):
                    if i == j or (next_comp is None):
                        continue
                    comp_next = self.arrays[j][self.indices[j]] if self.indices[j] >= 0 and self.indices[j] < len(self.arrays[j]) else None
                    result = next_comp.__lt__(comp_next) if self.forward else comp_next.__gt__(next_comp)
                    if result == 0:
                        continue
                    elif (result > 0) ^ self.forward:
                        next_comp = comp_next
                        for k in range(i):
                            comps[k] = None

        for i in range(len(self.arrays)):
            if comps[i] is not None:
                yield comps[i]
                self.indices[i] += -1 if self.forward else 1
