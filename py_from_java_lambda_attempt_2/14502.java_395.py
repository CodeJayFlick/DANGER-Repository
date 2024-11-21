Here is the translation of the given Java code into Python:

```Python
import numpy as np
import random
from typing import Any

class App:
    def __init__(self):
        self.logger = None  # Assuming you have a logger setup elsewhere in your program.

    @staticmethod
    def main(args: list[Any]) -> None:
        mw = ArrayTransposeMasterWorker()
        rows, columns = 10, 20
        input_matrix = np.random.randint(0, 100, (rows, columns))
        input_data = {"data": input_matrix}
        result = mw.get_result(input_data)
        if result is not None:
            print("Input Matrix:")
            print(result["data"])
        else:
            self.logger.info("Please enter non-zero input")

if __name__ == "__main__":
    app = App()
    app.main([])
```

Note that Python does not have direct equivalents for Java's `@Slf4j` and `var`. In the above code, I've used a logger (assuming you have one set up elsewhere in your program) to replace the former. For the latter, I've replaced it with explicit type declarations using Python's built-in `list` and `dict` types.

Also note that this translation assumes that the Java classes (`ArrayTransposeMasterWorker`, etc.) are implemented in a way that can be easily translated into equivalent Python code (e.g., by creating instances of these classes, calling their methods, etc.).