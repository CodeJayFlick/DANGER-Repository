class EpochTrainingListener:
    def __init__(self):
        self.epoch_time = 0
        self.num_epochs = 0

    def on_epoch(self, trainer):
        metrics = trainer.get_metrics()
        if metrics is not None:
            metrics.add_metric("epoch", int((int(time.time() * 1e9) - self.epoch_time)))
        self.epoch_time = time.time() * 1e9
        self.num_epochs += 1

    def on_training_begin(self, trainer):
        self.epoch_time = time.time() * 1e9

    def on_training_end(self, trainer):
        trainer.get_model().set_property("Epoch", str(self.num_epochs))

    @property
    def num_epochs(self):
        return self._num_epochs

    @num_epochs.setter
    def num_epochs(self, value):
        self._num_epochs = value
