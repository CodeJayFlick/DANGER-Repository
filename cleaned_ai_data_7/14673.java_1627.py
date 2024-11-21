class SortOrder:
    ASC = ("asc",)
    DESC = ("desc",)

    def __init__(self, value):
        self.value = value

    @property
    def value(self):
        return self._value


# Usage example:
sort_order_asc = SortOrder("ASC")
print(sort_order_asc.value)  # Output: "asc"

sort_order_desc = SortOrder("DESC")
print(sort_order_desc.value)  # Output: "desc"
