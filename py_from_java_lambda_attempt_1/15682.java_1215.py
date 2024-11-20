Here is the translation of the given Java code into Python:

```Python
import logging
from pathlib import Path
from typing import Callable

class SaveModelTrainingListener:
    def __init__(self, output_dir: str, override_model_name: str = None, checkpoint_frequency: int = -1):
        self.output_dir = output_dir
        self.override_model_name = override_model_name
        self.checkpoint_frequency = checkpoint_frequency
        if not self.output_dir:
            raise ValueError("Output directory cannot be empty")

    def on_epoch(self, trainer) -> None:
        epoch += 1

        if self.output_dir and self.checkpoint_frequency > 0 and (epoch % self.checkpoint_frequency == 0):
            self.save_model(trainer)

    def on_training_end(self, trainer) -> None:
        if self.checkpoint_frequency != -1 or epoch % self.checkpoint_frequency != 0:
            self.save_model(trainer)

    @property
    def override_model_name(self) -> str:
        return self.override_model_name

    @override_model_name.setter
    def override_model_name(self, value: str) -> None:
        self.override_model_name = value

    @property
    def checkpoint_frequency(self) -> int:
        return self.checkpoint_frequency

    @checkpoint_frequency.setter
    def checkpoint_frequency(self, value: int) -> None:
        self.checkpoint_frequency = value

    def set_save_model_callback(self, callback: Callable[[Trainer], None]) -> None:
        self.save_model_callback = callback

    def save_model(self, trainer):
        model = trainer.model
        if self.override_model_name is not None:
            model.name = self.override_model_name
        try:
            model.set_property("Epoch", str(epoch))
            if self.save_model_callback is not None:
                self.save_model_callback(trainer)
            model.save(Path(self.output_dir), model.name)
        except Exception as e:
            logging.error(f"Failed to save checkpoint: {e}")
```

Please note that Python does not have direct equivalent of Java's static logger, so I used the built-in `logging` module. Also, Python doesn't support checked exceptions like Java, but it has a different way of handling errors using try-except blocks.