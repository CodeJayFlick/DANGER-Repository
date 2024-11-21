class UDTF:
    def __init__(self):
        pass

    def before_start(self, parameters: dict, configurations: dict) -> None:
        # Your code here
        pass

    def transform_row(self, row: dict, collector: callable) -> None:
        # Your code here
        pass

    def transform_window(self, window: dict, collector: callable) -> None:
        # Your code here
        pass

    def terminate(self, collector: callable) -> None:
        # Your code here
        pass
