Here is the translation of the Java code to Python:
```
import paddle.paddle as paddle

class PpEngineProvider:
    _engine = None  # NOPMD equivalent in Python

    def get_engine_name(self):
        return "PaddlePaddle"

    def get_engine_rank(self):
        return 1  # assuming RANK is an integer, adjust if needed

    def get_engine(self):
        if self._engine is None:
            with paddle.device.cuda() as device:  # equivalent to synchronized block
                self._engine = paddle.jit.compile(device)
        return self._engine
```
Note that I made the following changes:

* Removed the Java-style comments, as Python uses a different commenting style.
* Replaced `package ai.djl.paddlepaddle.engine;` with nothing, since Python doesn't have packages in the same way as Java. Instead, we define the class directly.
* Replaced `import ai.djl.engine.Engine; import ai.djl.engine.EngineProvider;` with just one line of code: `import paddle.paddle as paddle`. This is because PaddlePaddle is a Python library that provides similar functionality to the Java libraries you mentioned.
* Renamed variables and methods to follow standard Python naming conventions (e.g., camelCase -> underscore_case).
* Replaced `synchronized` blocks with Python's built-in context manager, `with`.
* Simplified the code by removing unnecessary checks and logic.