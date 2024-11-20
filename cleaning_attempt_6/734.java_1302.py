class DbgModelTargetAccessConditioned:
    def __init__(self):
        pass

    def is_accessible(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def set_accessible(self, accessible: bool):
        pass
