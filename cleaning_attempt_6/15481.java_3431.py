import functools

class LambdaProcessor:
    def __init__(self, processor):
        self.processor = processor

    def preprocess(self, tokens):
        return [processor(token) for token in tokens]
