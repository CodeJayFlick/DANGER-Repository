import numpy as np
from djl import Model, Blocks, NDArray, NDManager, ArrayDataset, Trainer, TrainingConfig, Loss, Initializer
from typing import List, Tuple

class DatasetTest:
    def test_sequence_sampler(self):
        try:
            model = Model.newInstance("model")
            model.setBlock(Blocks.identityBlock())
            manager = model.getNDManager()
            data = np.arange(0, 100).reshape(-1, 1)
            dataset = ArrayDataset(data=data, sampling=BatchSampler(SequenceSampler(), 27, False))
            original_list: List[np.ndarray] = []
            with Trainer(model.newTrainer(config())) as trainer:
                for batch in trainer.iterateDataset(dataset):
                    original_list.append(batch.data.singleton_or_throw().toarray())
            assert len(original_list) == 4
        except Exception as e:
            print(f"Test failed: {e}")

    def test_random_sampler(self):
        try:
            model = Model.newInstance("model")
            model.setBlock(Blocks.identityBlock())
            manager = model.getNDManager()
            data = np.arange(0, 10).reshape(-1, 1)
            dataset = ArrayDataset(data=data, sampling=BatchSampler(RandomSampler(), 1, False))
            original_list: List[np.ndarray] = []
            with Trainer(model.newTrainer(config())) as trainer:
                for batch in trainer.iterateDataset(dataset):
                    original_list.append(batch.data.singleton_or_throw().toarray())
            assert len(original_list) == 10
        except Exception as e:
            print(f"Test failed: {e}")

    def test_batch_sampler(self):
        try:
            model = Model.newInstance("model")
            model.setBlock(Blocks.identityBlock())
            manager = model.getNDManager()
            data = np.arange(0, 100).reshape(-1, 1)
            dataset = ArrayDataset(data=data, sampling=BatchSampler(SequenceSampler(), 101, True))
            original_list: List[np.ndarray] = []
            with Trainer(model.newTrainer(config())) as trainer:
                for batch in trainer.iterateDataset(dataset):
                    original_list.append(batch.data.singleton_or_throw().toarray())
            assert len(original_list) == 1
        except Exception as e:
            print(f"Test failed: {e}")

    def test_array_dataset(self):
        try:
            model = Model.newInstance("model")
            model.setBlock(Blocks.identityBlock())
            manager = model.getNDManager()
            data = np.arange(0, 200).reshape(-1, 2)
            label = np.arange(100).reshape(-1, 1)
            dataset = ArrayDataset(data=[data], labels=label, sampling=20, False)
            index: int = 0
            with Trainer(model.newTrainer(config())) as trainer:
                for batch in trainer.iterateDataset(dataset):
                    assert np.array_equal(batch.data.singleton_or_throw(), data[index:index+40].reshape(-1, 2))
                    assert np.array_equal(batch.labels.singleton_or_throw(), label[index:index+20].reshape(-1, 1))
                    index += 20
        except Exception as e:
            print(f"Test failed: {e}")

    def test_multithreading(self):
        try:
            model = Model.newInstance("model")
            model.setBlock(Blocks.identityBlock())
            manager = model.getNDManager()
            executor = ThreadPoolExecutor(max_workers=5)
            cifar10 = Cifar10.builder().opt_manager(manager).set_sampling(2, True).build()
            threaded_config = config().opt_executor_service(executor)
            with Trainer(model.newTrainer(threaded_config)) as trainer:
                for batch in trainer.iterateDataset(cifar10):
                    batch.close()
            executor.shutdown()
        except Exception as e:
            print(f"Test failed: {e}")

    def test_dataset_to_array(self):
        try:
            manager = NDManager.new_base_manager()
            dataset = ArrayDataset(data=manager.ones((5, 4)), sampling=32, False)
            labels = manager.zeros((5, 2))
            converted = dataset.to_array()
            data: List[np.ndarray] = converted[0]
            label: List[np.ndarray] = converted[1]
            assert len(data) == 5
        except Exception as e:
            print(f"Test failed: {e}")

    def config(self):
        return TrainingConfig(loss=Loss.l2_loss(), initializer=Initializer.ones())

# Usage example:

test_sequence_sampler()
test_random_sampler()
test_batch_sampler()
test_array_dataset()
test_multithreading()
test_dataset_to_array()

