Here is the translation of the given Java code into equivalent Python:

```Python
import time
import json
from typing import Dict

class Cell:
    def __init__(self):
        pass


class CandyGame:
    def __init__(self, rows: int, pool: 'CellPool'):
        self.rows = rows
        self.pool = pool

    def print_game_status(self) -> None:
        # implement this method as per your requirement
        pass

    def round(self, elapsed_time: float, given_time: float) -> None:
        # implement this method as per your requirement
        pass


class CellPool:
    def __init__(self, size: int):
        self.size = size
        self.cells = [Cell() for _ in range(size)]


def main():
    given_time = 50  # ms
    to_win = 500  # points
    points_won = 0

    start = time.time()
    end = start
    round_num = 1

    while points_won < to_win and end - start < given_time:
        round_num += 1
        pool = CellPool(3 * 3 + 5)  # numOfRows * numOfRows + 5
        game = CandyGame(3, pool)
        
        if round_num > 1:
            print("Refreshing..")
        else:
            print("Starting game..")

        game.print_game_status()
        end = time.time()

        game.round((end - start), given_time)
        points_won += game.total_points
        end = time.time()

    print("Game Over")
    
    if points_won >= to_win:
        print(f"{points_won}")
        print("You win!!")
    else:
        print(f"{points_won}")
        print("Sorry, you lose!")


if __name__ == "__main__":
    main()
```

Please note that the Java code uses a logging mechanism which is not directly translatable to Python. The equivalent functionality in Python would be achieved using its built-in `print` function or any other logging module like `logging`.