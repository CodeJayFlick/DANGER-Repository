import ai_djl_translate as translate

class TrtPredictor(I, O):
    def __init__(self, model: 'TrtModel', translator: 'Translator[I, O]', session: 'TrtSession'):
        super().__init__(model, translator, False)
        self.block = session

    def close(self):
        super().close()
        (self.block).close()

class TrtModel:
    pass

class Translator(I, O):
    pass

class TrtSession:
    pass
