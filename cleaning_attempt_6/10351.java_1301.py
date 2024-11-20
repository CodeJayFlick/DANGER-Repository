class ClassExclusionFilter:
    def __init__(self, *exclusions):
        self.exclusion_set = set(exclusions)

    def accepts(self, c):
        return c not in self.exclusion_set
