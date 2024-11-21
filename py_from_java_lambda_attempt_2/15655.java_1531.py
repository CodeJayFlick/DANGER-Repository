Here is the translation of the given Java code into Python:

```Python
import logging
from typing import Tuple

class EasyHpo:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def fit(self) -> Tuple['Model', 'TrainingResult']:
        training_set, validate_set = self.get_dataset(Dataset.Usage.TRAIN), self.get_dataset(Dataset.Usage.TEST)
        hyper_params = self.setup_hyperparams()
        hp_optimizer = HpORandom(hyper_params)

        for _ in range(self.num_hyperparameter_tests()):
            hp_vals = hp_optimizer.next_config()
            trained_model, training_result = self.train(hp_vals, training_set, validate_set)
            loss = training_result.get_validate_loss()
            hp_optimizer.update(hp_vals, loss)
            self.logger.info(f"hp test {_}/{self.num_hyperparameter_tests()} - Loss {loss} - {hp_vals}")

        best_hp_vals = hp_optimizer.get_best().key
        trained_model, training_result = self.train(best_hp_vals, training_set, validate_set)
        self.save_model(trained_model, training_result)

    def train(self, hp_vals: 'HpSet', training_set: RandomAccessDataset, validate_set: RandomAccessDataset) -> Tuple['Model', 'TrainingResult']:
        model = self.build_model(hp_vals)
        config = self.setup_training_config(hp_vals)

        try:
            trainer = model.new_trainer(config)
            trainer.set_metrics(Metrics())
            trainer.initialize(self.input_shape(hp_vals))
            EasyTrain.fit(trainer, self.num_epochs(hp_vals), training_set, validate_set)
            return model, trainer.get_training_result()
        except Exception as e:
            raise TranslateException(str(e))

    def setup_hyperparams(self) -> 'HpSet':
        # abstract method
        pass

    def get_dataset(self, usage: Dataset.Usage) -> RandomAccessDataset:
        # abstract method
        pass

    def setup_training_config(self, hp_vals: 'HpSet') -> TrainingConfig:
        # abstract method
        pass

    def build_model(self, hp_vals: 'HpSet') -> 'Model':
        # abstract method
        pass

    def input_shape(self, hp_vals: 'HpSet') -> Shape:
        # abstract method
        pass

    def num_epochs(self, hp_vals: 'HpSet') -> int:
        # abstract method
        pass

    def num_hyperparameter_tests(self) -> int:
        # abstract method
        pass

    def save_model(self, model: 'Model', training_result: 'TrainingResult'):
        # abstract method
        pass


class HpORandom:
    def __init__(self, hyper_params):
        self.hyper_params = hyper_params

    def next_config(self) -> 'HpSet':
        # implementation of random search for hp values
        pass

    def update(self, hp_vals: 'HpSet', loss: float):
        # implementation to update the best hp set based on the given loss value
        pass


class Metrics:
    def get_validate_loss(self) -> float:
        # abstract method
        pass


class TrainingConfig:
    pass


class Model:
    def new_trainer(self, config: 'TrainingConfig') -> Trainer:
        # implementation of model trainer
        pass

    def close(self):
        # abstract method
        pass


class Shape:
    pass


class RandomAccessDataset:
    pass


class TranslateException(Exception):
    pass
```

Please note that this is a direct translation from Java to Python, and you may need to adjust the code based on your specific requirements.