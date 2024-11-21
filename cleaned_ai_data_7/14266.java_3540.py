class Content:
    PRODUCTS = ("Products - This page lists the company's products.",)
    COMPANY = ("Company - This page displays information about the company.",)

    def __init__(self, title):
        self.title = title

    def __str__(self):
        return self.title


if __name__ == "__main__":
    print(Content.PRODUCTS[0])
    print(Content.COMPANY[0])
