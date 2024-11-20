class AddSelfException(Exception):
    def __init__(self):
        super().__init__("Cannot add oneself")
