class AdvancedSorceress:
    def __init__(self):
        self.tobacco = None

    def smoke(self):
        if self.tobacco is not None:
            self.tobacco.smoke(self)
