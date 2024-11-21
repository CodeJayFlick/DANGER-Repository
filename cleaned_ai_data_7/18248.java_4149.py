class FilterType:
    VALUE_FILTER = ("value",)
    TIME_FILTER = ("time",)
    GROUP_BY_FILTER = ("group by",)

    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name
