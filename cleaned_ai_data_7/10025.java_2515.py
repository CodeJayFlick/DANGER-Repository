import threading

class TestIncrementalThreadedTableModelListener:
    def __init__(self, model, spy):
        super().__init__(model, spy)

    def reset(self, model):
        super().reset(model)
        # sometimes the test changes the model--this allows us to listen to the latest model
        model.add_listener(self)
