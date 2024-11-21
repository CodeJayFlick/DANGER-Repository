class PaddlePredictor:
    def __init__(self, handle):
        self.handle = handle

    def copy(self):
        return PaddlePredictor(JniUtils.clone_predictor(self))

    def close(self):
        JniUtils.delete_predictor(self)
