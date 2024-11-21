class Size:
    SMALL = ("small",)
    NORMAL = ("normal",)
    LARGE = ("large",)

    def __init__(self, title):
        self.title = title

    def __str__(self):
        return self.title
