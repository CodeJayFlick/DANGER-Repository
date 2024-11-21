import ai.djl.repository.zoo.ModelZoo
from ai.djl.engine import Engine

class RequireZoo:
    def __init__(self):
        pass

    @staticmethod
    def basic():
        if not ModelZoo.has_model_zoo("ai.djl.zoo"):
            raise ValueError(
                "The basic model zoo is required, but not found."
                + "Please install it by following http://docs.djl.ai/model-zoo/index.html#installation"
            )

    @staticmethod
    def mxnet():
        if not ModelZoo.has_model_zoo("ai.djl.mxnet"):
            raise ValueError(
                "The MXNet model zoo is required, but not found."
                + "Please install it by following http://docs.djl.ai/engines/mxnet/mxnet-model-zoo/index.html#installation"
            )
        if not Engine.has_engine("MXNet"):
            raise ValueError(
                "The MXNet engine is required, but not found."
                + "Please install it by following http://docs.djl.ai/engines/mxnet/mxnet-engine/index.html#installation"
            )

    @staticmethod
    def pytorch():
        if not ModelZoo.has_model_zoo("ai.djl.pytorch"):
            raise ValueError(
                "The PyTorch model zoo is required, but not found."
                + "Please install it by following http://docs.djl.ai/pytorch/pytorch-model-zoo/index.html#installation"
            )
        if not Engine.has_engine("PyTorch"):
            raise ValueError(
                "The PyTorch engine is required, but not found."
                + "Please install it by following http://docs.djl.ai/pytorch/pytorch-engine/index.html#installation"
            )

    @staticmethod
    def tensorflow():
        if not ModelZoo.has_model_zoo("ai.djl.tensorflow"):
            raise ValueError(
                "The TensorFlow model zoo is required, but not found."
                + "Please install it by following http://docs.djl.ai/engines/tensorflow/tensorflow-model-zoo/index.html#installation"
            )
        if not Engine.has_engine("TensorFlow"):
            raise ValueError(
                "The TensorFlow engine is required, but not found."
                + "Please install it by following http://docs.djl.ai/engines/tensorflow/tensorflow-engine/index.html#installation"
            )

