import unittest
from ai_djl_examples_training_transferlearning import TrainResnetWithCifar10
from training import TrainingResult
import os

class TestTrainResNet(unittest.TestCase):

    SEED = 1234

    def test_train_res_net(self):
        args = ["-e", "2", "-g", "4", "-m", "10", "-s", "-p"]
        result = TrainResnetWithCifar10.run_example(args)
        self.assertIsNotNone(result)

    @unittest.skipIf(not os.environ.get("nightly"), "Nightly only")
    def test_train_res_net_symbolic_nightly(self):
        if Engine().get_gpu_count() > 0:
            args = ["-e", "10", "-g", "4", "-s", "-p"]
            Engine().set_random_seed(SEED)
            result = TrainResnetWithCifar10.run_example(args)
            self.assertIsNotNone(result)

            self.assertGreaterEqual(result.get_train_evaluation("Accuracy"), 0.8)
            self.assertGreaterEqual(result.get_validate_evaluation("Accuracy"), 0.68)
            self.assertLess(result.get_validate_loss(), 1.1)

    @unittest.skipIf(not os.environ.get("nightly"), "Nightly only")
    def test_train_res_net_imperative_nightly(self):
        if Engine().get_gpu_count() > 0:
            args = ["-e", "10", "-g", "4"]
            Engine().set_random_seed(SEED)
            result = TrainResnetWithCifar10.run_example(args)
            self.assertIsNotNone(result)

            self.assertGreaterEqual(result.get_train_evaluation("Accuracy"), 0.9)
            self.assertGreaterEqual(result.get_validate_evaluation("Accuracy"), 0.75)
            self.assertLess(result.get_validate_loss(), 1)


if __name__ == "__main__":
    unittest.main()
