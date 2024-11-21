class HpOptimizer:
    def __init__(self):
        pass

    def next_config(self) -> dict:
        # Implement your logic here for generating the next set of hyperparameters to test.
        return {}

    def update(self, config: dict, loss: float):
        # Update the optimizer with the results of a hyperparameter test.
        pass

    def get_loss(self, config: dict) -> float:
        # Return the recorded loss. If no training has been done yet, raise an exception.
        if not hasattr(self, 'losses'):
            raise ValueError("No losses have been recorded for this set of hyperparameters.")
        return self.losses[config]

    def get_best(self) -> tuple:
        # Return the best hyperparameters and loss. If no training has been done yet, raise an exception.
        if not hasattr(self, 'best_config') or not hasattr(self, 'best_loss'):
            raise ValueError("No losses have been recorded for this optimizer.")
        return (self.best_config, self.best_loss)
