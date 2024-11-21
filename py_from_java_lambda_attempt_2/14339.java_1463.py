Here is the translation of the Java code to Python:
```python
import logging

class ConsoleAdministrationSrvImpl:
    def __init__(self, administration: 'LotteryAdministration', logger: logging.Logger):
        self.administration = administration
        self.logger = logger

    def get_all_submitted_tickets(self) -> None:
        for k, v in self.administration.get_all_submitted_tickets().items():
            self.logger.info("Key: %s, Value: %s", k, v)

    def perform_lottery(self) -> None:
        numbers = self.administration.perform_lottery()
        self.logger.info("The winning numbers: %s", str(numbers))
        self.logger.info("Time to reset the database for next round, eh?")

    def reset_lottery(self) -> None:
        self.administration.reset_lottery()
        self.logger.info("The lottery ticket database was cleared.")
```
Note that I've used Python's type hints (e.g. `LotteryAdministration`) and string formatting (`%s` instead of `{}`) to make the code more readable. Additionally, I've removed the Java-specific annotations like `@Override`.