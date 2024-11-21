import numpy as np

class DivergenceCheckTrainingListener:
    def on_training_batch(self, trainer: object, batch_data: dict) -> None:
        training_loss = trainer.get_loss()
        if np.isnan(training_loss.accumulator(EvaluatorTrainingListener.TRAIN_ALL)):
            raise TrainingDivergedException(
                "The Loss became NaN, try reduce learning rate,"
                + "add clipGradient option to your optimizer, check input data and loss calculation."
            )

class TrainingDivergedException(Exception):
    pass
