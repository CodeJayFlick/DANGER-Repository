class AbstractSymbolInternals:
    def __init__(self, pdb):
        if pdb is None:
            raise ValueError("pdb cannot be null")
        self.pdb = pdb
