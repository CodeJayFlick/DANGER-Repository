class IrisFlower:
    def __init__(self, sepal_length: float, sepal_width: float, petal_length: float, petal_width: float):
        self.sepal_length = sepal_length
        self.sepal_width = sepal_width
        self.petal_length = petal_length
        self.petal_width = petal_width

    def get_sepal_length(self) -> float:
        return self.sepal_length

    def get_sepal_width(self) -> float:
        return self.sepal_width

    def get_petal_length(self) -> float:
        return self.petal_length

    def get_petal_width(self) -> float:
        return self.petal_width
