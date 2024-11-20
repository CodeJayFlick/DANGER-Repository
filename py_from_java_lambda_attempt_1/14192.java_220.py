Here is the translation of the given Java code into Python:

```Python
import logging

class DwarvenMineWorker:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def go_to_sleep(self):
        self.logger.info("{} goes to sleep.".format(self.name()))

    def wake_up(self):
        self.logger.info("{} wakes up.".format(self.name()))

    def go_home(self):
        self.logger.info("{} goes home.".format(self.name()))

    def go_to_mine(self):
        self.logger.info("{} goes to the mine.".format(self.name()))

    def action(self, action: str) -> None:
        if action == "GO_TO_SLEEP":
            self.go_to_sleep()
        elif action == "WAKE_UP":
            self.wake_up()
        elif action == "GO_HOME":
            self.go_home()
        elif action == "GO_TO_MINE":
            self.go_to_mine()
        # Add more actions as needed
        else:
            self.logger.info("Undefined action")

    def perform_actions(self, *actions: str) -> None:
        for action in actions:
            self.action(action)

    @abstractmethod
    def work(self):
        pass

    @abstractmethod
    def name(self) -> str:
        pass


class Action(str, Enum):
    GO_TO_SLEEP = "GO_TO_SLEEP"
    WAKE_UP = "WAKE_UP"
    GO_HOME = "GO_HOME"
    GO_TO_MINE = "GO_TO_MINE"
    WORK = "WORK"


if __name__ == "__main__":
    worker = DwarvenMineWorker()
    # Example usage
    actions = [Action.GO_TO_SLEEP, Action.WORK]
    worker.perform_actions(*actions)
```

Please note that Python does not have an exact equivalent to Java's `@Slf4j` annotation. The logging functionality is implemented using the built-in `logging` module in this translation.