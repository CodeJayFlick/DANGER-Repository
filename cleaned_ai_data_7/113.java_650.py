class MemviewService:
    def __init__(self):
        pass

    def set_boxes(self, box_list: list) -> None:
        # implement this method in your subclass
        pass

    def init_views(self) -> None:
        # implement this method in your subclass
        pass

    def set_program(self, current_program: object) -> None:
        # implement this method in your subclass
        self.current_program = current_program

    def get_provider(self) -> object:
        # implement this method in your subclass
        return None  # or any other default value you want to return
