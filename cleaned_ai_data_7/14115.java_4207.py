class Weekday:
    MONDAY = ("Monday",)
    TUESDAY = ("Tuesday",)
    WEDNESDAY = ("Wednesday",)
    THURSDAY = ("Thursday",)
    FRIDAY = ("Friday",)
    SATURDAY = ("Saturday",)
    SUNDAY = ("Sunday",)

    def __init__(self, description):
        self.description = description

    def __str__(self):
        return self.description
