class TestVertex:
    def __init__(self, name):
        super().__init__(name)

    def get_component(self) -> object:
        # this default test vertex is not meant to be displayed, so None is fine
        return None

