class PatternValue:
    def __init__(self):
        pass

    def get_min_value(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_max_value(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")
