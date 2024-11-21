class PotatoPeelingTask:
    TIME_PER_POTATO = 200

    def __init__(self, num_potatoes):
        super().__init__(num_potatoes * self.TIME_PER_POTATO)

    def __str__(self):
        return f"{type(self).__name__} {super().__str__()}"
