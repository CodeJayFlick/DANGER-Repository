import mxnet as mx
import numpy as np
from djl import Model, Blocks, NDArray, NDArrays, NDManager, Shape, Loss
from djl.testing.Assertions import assertAlmostEquals

class MxGradientCollectorIntegrationTest:
    def testMxAutograd(self):
        model = Model.newInstance("model")
        manager = model.getNDManager()
        
        model.setBlock(Blocks.identityBlock())
        trainer = model.newTrainer(DefaultTrainingConfig(Loss.l2Loss()).optInitializer(mx.init.Ones(), mx.symbol.ParameterType.WEIGHT))
        
        with GradientCollector(trainer) as grad_col:
            lhs = NDArray.manager(manager).create(np.array([[6, -9, -12], [15, 0, 4]]), Shape((2,3)))
            rhs = NDArray.manager(manager).create(np.array([[-4], [-4], [2]]), Shape((1,3)))
            expected = NDArray.manager(manager).create(np.array([[2, 3, -4], [2, 3, -4]]), Shape((2,3)))

            lhs.setRequiresGradient(True)
            
            result = NDArrays.dot(lhs, rhs)
            grad_col.backward(result)
            grad = lhs.getGradient()
            assertAlmostEquals(grad, expected)

            # test close and get again
            grad.close()
            grad2 = lhs.getGradient()
            assertAlmostEquals(grad2, expected)


if __name__ == "__main__":
    MxGradientCollectorIntegrationTest().testMxAutograd()

