class EmptyDataSet:
    def __init__(self):
        super().__init__([], [])

    def hasNext_without_constraint(self) -> bool:
        return False

    def next_without_constraint(self) -> object:
        return None
