import mxnet as mx
from dgl import backend as F

class MxNDArrayIndexer:
    def __init__(self, manager):
        self.manager = manager

    def get(self, array, full_pick):
        array = self.manager.from_array(array)
        params = {'axis': full_pick.axis, 'keepdims': True, 'mode': 'wrap'}
        return mx.nd.pick(array, full_pick.indices, **params)

    def get(self, array, full_slice):
        array = self.manager.from_array(array)
        params = {
            'begin': full_slice.min,
            'end': full_slice.max,
            'step': full_slice.step
        }
        result = mx.nd.slice(array, tuple(params['begin']), tuple(params['end']), step=params['step'])
        if len(full_slice.to_squeeze) > 0:
            old_result = result.copy()
            result = F.squeeze(result, axes=full_slice.to_squeeze)
            old_result.dispose()
        return result

    def set(self, array, full_slice, value):
        array = self.manager.from_array(array)
        params = {
            'begin': full_slice.min,
            'end': full_slice.max,
            'step': full_slice.step
        }
        if isinstance(value, mx.nd.NDArray):
            prepare_value = [value]
            while len(full_slice.shape) > value.shape[0]:
                value = F.reshape(value, (1,) + value.shape)
            value = F.broadcast_to(value, tuple(full_slice.shape))
            array[:] = mx.nd.slice(array, *params['begin'], step=params['step'])
        else:
            params['scalar'] = value
            array[:] = mx.nd.slice_assign(array, *params['begin'], step=params['step'], scalar=value)
