import mxnet as mx
from mxnet import gluon
from mxnet.gluon.data.dataloader import DataLoader
from mxnet.ndarray import NDArray, NDList
from mxnet.optimizer import Optimizer


class MxParameterServer:
    def __init__(self, optimizer):
        self.callback = OptimizerCallback(optimizer)
        self.priority = 0

    def init(self, parameter_id, values):
        keys = [parameter_id] * len(values)
        vals = NDList(*values)
        mx.nd.parameter_store_init(len(keys), keys, vals)

    def update(self, parameter_id, grads, params):
        grad_keys = [parameter_id] * len(grads)
        param_keys = [parameter_id] * len(params)
        mx.nd.parameter_store_push_pull(
            -self.priority,
            len(grads),
            grad_keys,
            len(params),
            param_keys,
            NDList(*grads),
            NDList(*params))
        self.priority += 1

    def close(self):
        if hasattr(self, 'handle'):
            handle = getattr(self, 'handle')
            mx.nd.parameter_store_close(handle)
            setattr(self, 'handle', None)


class OptimizerCallback:
    def __init__(self, optimizer):
        self.optimizer = optimizer

    def apply(self, parameter_id, recv, local, handle):
        try:
            grad = NDArray(recv.asnumpy())
            weight = NDArray(local.asnumpy())
            self.optimizer.update(parameter_id, weight, grad)
        except Exception as e:
            print(f"Error: {e}")
