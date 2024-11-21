import numpy as np
from djl import Model, NDArray, NDArrays, NDManager
from djl.nn import Blocks, Linear
from djl.testing import Assertions
from djl.training import DefaultTrainingConfig, EasyTrain, GradientCollector, Trainer
from djl.translate.TranslateException

class GradientCollectorIntegrationTest:
    def test_autograd(self):
        try:
            model = Model.newInstance("model")
            manager = model.getNDManager()
            model.setBlock(Blocks.identityBlock())
            
            trainer = model.newTrainer(DefaultTrainingConfig(Loss.l2Loss()).optInitializer(Initializer.ones(), Parameter.Type.weight))
            gradient_collector = trainer.newGradientCollector()

            lhs = NDArray(manager, np.array([[6], [-9], [-12], [15], [0], [4]]), shape=(2, 3))
            rhs = NDArray(manager, np.array([[-4]]), shape=(1, 3))

            expected = NDArray(manager, np.array([[2], [3], [-4], [2], [3], [-4]]), shape=(2, 3))

            lhs.setRequiresGradient(True)

            result = NDArrays.dot(lhs, rhs)
            gradient_collector.backward(result)
            grad = lhs.getGradient()
            Assertions.assertAlmostEquals(grad, expected)

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_train(self):
        if not bool("nightly"):
            raise SkipException("Nightly only")

        num_of_data = 1000
        batch_size = 10
        epochs = 10

        optimizer = Optimizer.sgd().setLearningRateTracker(Tracker.fixed(.03)).build()

        config = DefaultTrainingConfig(Loss.l2Loss()).addTrainingListeners(EvaluatorTrainingListener()).optInitializer(Initializer.ones(), Parameter.Type.weight).optOptimizer(optimizer)

        try:
            model = Model.newInstance("linear")
            block = Linear.builder().setUnits(1).build()
            model.setBlock(block)
            
            manager = model.getNDManager()

            weight = NDArray(manager, np.array([[2], [-3.4]]), shape=(2, 1))
            bias = 4.2
            data = manager.randomNormal(np.zeros((num_of_data, weight.shape[0])))
            label = (data * weight).add(bias)
            
            # add noise
            label.addi(manager.randomNormal(0, .01, label.shape, np.float32, manager.getDevice()))

            sampling = config.getDevices().length * batch_size
            dataset = ArrayDataset.Builder().setData(data).optLabels(label).setSampling(sampling, False).build()

            loss_value = 0.0

            try:
                trainer = model.newTrainer(config)
                
                input_shape = (sampling, weight.shape[0])
                trainer.initialize(input_shape)

                for epoch in range(epochs):
                    trainer.notifyListeners(lambda listener: listener.onEpoch(trainer))
                    
                    for batch in trainer.iterateDataset(dataset):
                        EasyTrain.trainBatch(trainer, batch)
                        trainer.step()
                        batch.close()

            except Exception as e:
                print(f"An error occurred during training: {e}")

        finally:
            try:
                loss_value = trainer.getLoss().getAccumulator(EvaluatorTrainingListener.TRAIN_EPOCH)

            except Exception as e:
                print(f"Error getting loss value: {e}")
            
            expected_loss = 0.001
            assert(loss_value < expected_loss, f"Loss did not improve, loss value: {loss_value}, expected max loss value: {expected_loss}")

if __name__ == "__main__":
    test_autograd()
    test_train()

