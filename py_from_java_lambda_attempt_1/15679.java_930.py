Here is the translation of the Java code into Python:

```Python
import logging
from typing import List

class LoggingTrainingListener:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.frequency = 1
        self.num_epochs = 0
        self.training_progress_bar = None
        self.validation_progress_bar = None

    def on_epoch(self, trainer: object) -> None:
        self.num_epochs += 1
        if self.frequency > 1 and self.num_epochs % self.frequency != 1:
            return
        
        self.logger.info("Epoch {} finished.".format(self.num_epochs))

        metrics = trainer.get_metrics()
        if metrics is not None:
            loss = trainer.get_loss()
            status = get_evaluators_status(metrics, trainer.get_evaluators(), "TRAIN_EPOCH", Short.MAX_VALUE)
            self.logger.info("Train: {}".format(status))
            
            metric_name = EvaluatorTrainingListener.metric_name(loss, "VALIDATE_EPOCH")
            if metrics.has_metric(metric_name):
                status = get_evaluators_status(metrics, trainer.get_evaluators(), "VALIDATE_EPOCH", Short.MAX_VALUE)
                if not status:
                    self.logger.info("validation has not been run.")
            else:
                self.logger.info("validation has not been run.")

    def on_training_batch(self, trainer: object, batch_data: object) -> None:
        if self.frequency > 1 and self.num_epochs % self.frequency != 1:
            return
        
        if self.training_progress_bar is None:
            self.training_progress_bar = ProgressBar("Training", batch_data.get_batch().get_progress_total())
        
        self.training_progress_bar.update(batch_data.get_batch().get_progress(), get_training_status(trainer, batch_data.get_batch().size()))

    def on_validation_batch(self, trainer: object, batch_data: object) -> None:
        if self.frequency > 1 and self.num_epochs % self.frequency != 1:
            return
        
        if self.validation_progress_bar is None:
            self.validation_progress_bar = ProgressBar("Validating", batch_data.get_batch().get_progress_total())
        
        self.validation_progress_bar.update(batch_data.get_batch().get_progress())

    def on_training_begin(self, trainer: object) -> None:
        devices_msg = ""
        for device in trainer.get_devices():
            if Device.Type.CPU == device.device_type:
                devices_msg += "CPU"
            else:
                devices_msg += str(device)
        
        self.logger.info("Training on: {}".format(devices_msg))

    def on_training_end(self, trainer: object) -> None:
        metrics = trainer.get_metrics()
        if metrics is not None:
            p50 = 0
            p90 = 0
            
            for metric_name in ["train", "forward", "training-metrics", "backward", "step", "epoch"]:
                if metrics.has_metric(metric_name):
                    value = metrics.latest_metric(metric_name).value
                    
                    if metric_name == "train":
                        p50 += value / 1_000_000_000
                        p90 += value / 1_000_000_000
                    elif metric_name in ["forward", "backward"]:
                        p50 += value / 1_000_000
                        p90 += value / 1_000_000
                    else:
                        if metric_name == "step":
                            p50 += value / 1_000_000_000
                            p90 += value / 1_000_000_000
                        elif metric_name == "epoch":
                            p50 += value / 1_000_000_000_0000
                            p90 += value / 1_000_000_000_0000
                    
                    self.logger.info("{} P50: {:.3f} ms, P90: {:.3f} ms".format(metric_name, p50, p90))
```

Note that Python does not have direct equivalent of Java's `Logger` and `ProgressBar`. I used the built-in `logging` module for logging and created a simple class `ProgressBar` to mimic the behavior.