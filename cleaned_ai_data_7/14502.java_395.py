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
