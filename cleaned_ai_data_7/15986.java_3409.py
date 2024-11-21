import paddle.paddle as paddle

class PpEngineProvider:
    _engine = None  # NOPMD equivalent in Python

    def get_engine_name(self):
        return "PaddlePaddle"

    def get_engine_rank(self):
        return 1  # assuming RANK is an integer, adjust if needed

    def get_engine(self):
        if self._engine is None:
            with paddle.device.cuda() as device:  # equivalent to synchronized block
                self._engine = paddle.jit.compile(device)
        return self._engine
