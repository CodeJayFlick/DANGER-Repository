class VectorCompare:
    def __init__(self):
        self.dotproduct = 0.0
        self.acount = 0
        self.bcount = 0
        self.intersectcount = 0
        self.min = 0
        self.max = 0
        self.numflip = 0
        self.diff = 0

    def fill_out(self):
        if self.acount < self.bcount:
            self.min = self.acount
            self.max = self.bcount
        else:
            self.min = self.bcount
            self.max = self.acount
        self.diff = self.max - self.min
        self.numflip = self.min - self.intersectcount

    def __str__(self):
        return f"VectorCompare:\n  Result of the dot product      = {self.dotproduct}\n   # of hashes in first vector    = {self.acount}\n   # of hashes in second vector   = {self.bcount}\n   # of hashes in common          = {self.intersectcount}\n  Minimum vector count           = {self.min}\n  Maximum vector count           = {self.max}\n  Number of hashes flipped       = {self.numflip}\n  Difference in # of hashes      = {self.diff}"
