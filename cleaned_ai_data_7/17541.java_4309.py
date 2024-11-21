class UDTFSign:
    def __init__(self):
        pass

    def set_transformer(self):
        self.transformer = lambda x: math.copysign(1, x)
