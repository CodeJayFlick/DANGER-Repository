import mxnet as mx
from mxnet import gluon, ndarray, npx
npx.set_np()

class MxBackendOptimizationTest:
    def test_optimized_for(self):
        try:
            manager = ndarray.NDManager()
            symbol = mx.gluon.nn.SymbolBlock.load(
                '../mxnet-model-zoo/src/test/resources/mlrepo/model/cv/image_classification/ai/djl/mxnet/resnet/0.0.1/resnet50_v1-symbol.json',
                manager, device_type='cpu'
            )
            optimized = symbol.optimize_for('test', 'cpu')
            optimized.close()
        finally:
            manager.free_all_devices()

if __name__ == "__main__":
    test_optimized_for = MxBackendOptimizationTest().test_optimized_for()
