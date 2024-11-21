import logging
from concurrent.futures import ThreadPoolExecutor
from functools import partial

# Set up logger
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

class App:
    def __init__(self):
        pass

    @staticmethod
    def main():
        LOGGER.info("Program started")

        # Create a list of tasks to be executed
        tasks = [
            {"task": "PotatoPeelingTask", "args": [3]},
            {"task": "PotatoPeelingTask", "args": [6]},
            {"task": "CoffeeMakingTask", "args": [2]},
            {"task": "CoffeeMakingTask", "args": [6]},
            {"task": "PotatoPeelingTask", "args": [4]},
            {"task": "CoffeeMakingTask", "args": [2]},
            {"task": "PotatoPeelingTask", "args": [4]},
            {"task": "CoffeeMakingTask", "args": [9]},
            {"task": "PotatoPeelingTask", "args": [3]},
            {"task": "CoffeeMakingTask", "args": [2]},
            {"task": "PotatoPeelingTask", "args": [4]},
            {"task": "CoffeeMakingTask", "args": [2]},
            {"task": "CoffeeMakingTask", "args": [7]},
            {"task": "PotatoPeelingTask", "args": [4]},
            {"task": "PotatoPeelingTask", "args": [5]}
        ]

        # Create a thread pool with 3 threads
        executor = ThreadPoolExecutor(max_workers=3)

        # Allocate new worker for each task and execute it in the thread pool
        list(map(lambda x: executor.submit(partial(task_handler, **x)), tasks))

        # Shut down the thread pool
        executor.shutdown()
        LOGGER.info("Program finished")

def task_handler(task_type, *args):
    if task_type == "PotatoPeelingTask":
        print(f"Executing Potato Peeling Task with {len(args)} potatoes")
    elif task_type == "CoffeeMakingTask":
        print(f"Executing Coffee Making Task for {len(args)} cups of coffee")
