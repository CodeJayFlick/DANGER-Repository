class MenuItem:
    HOME = ("Home",)
    PRODUCTS = ("Products",)
    COMPANY = ("Company",)

    def __init__(self, title):
        self.title = title

    def __str__(self):
        return self.title[0]
