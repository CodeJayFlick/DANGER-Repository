class CoffeeMakingTask:
    TIME_PER_CUP = 100

    def __init__(self, num_cups):
        super().__init__(num_cups * self.TIME_PER_CUP)

    def __str__(self):
        return f"{type(self).__name__} {super().__str__()}"
