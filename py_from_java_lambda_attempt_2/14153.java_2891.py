Here is the translation of the given Java code into Python:

```Python
import logging
from datetime import date

class App:
    ACCOUNT_OF_DAENERYS = 1
    ACCOUNT_OF_JON = 2

    def __init__(self):
        self.event_processor = None
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def run(self):
        self.event_processor = DomainEventProcessor()
        self.logger.info("Running the system first time............")
        self.event_processor.reset()

        self.logger.info("Creating the accounts............")

        self.event_processor.process(AccountCreateEvent(0, date.today().timestamp(), App.ACCOUNT_OF_DAENERYS, "Daenerys Targaryen"))
        self.event_processor.process(AccountCreateEvent(1, date.today().timestamp(), App.ACCOUNT_OF_JON, "Jon Snow"))

        self.logger.info("Do some money operations............")

        self.event_processor.process(MoneyDepositEvent(2, date.today().timestamp(), App.ACCOUNT_OF_DAENERYS, 100000))
        self.event_processor.process(MoneyDepositEvent(3, date.today().timestamp(), App.ACCOUNT_OF_JON, 100))

        self.event_processor.process(MoneyTransferEvent(4, date.today().timestamp(), 10000, App.ACCOUNT_OF_DAENERYS, App.ACCOUNT_OF_JON))

        self.logger.info("...............State:............")
        print(AccountAggregate.get_account(App.ACCOUNT_OF_DAENERYS))
        print(AccountAggregate.get_account(App.ACCOUNT_OF_JON))

        self.logger.info("At that point system had a shut down, state in memory is cleared............")

        AccountAggregate.reset_state()

        self.logger.info("Recover the system by the events in journal file............")
        
        self.event_processor = DomainEventProcessor()
        self.event_processor.recover()

        self.logger.info("...............Recovered State:............")
        print(AccountAggregate.get_account(App.ACCOUNT_OF_DAENERYS))
        print(AccountAggregate.get_account(App.ACCOUNT_OF_JON))

if __name__ == "__main__":
    app = App()
    app.run()
```

Note that Python does not have direct equivalent of Java's `@Slf4j` annotation. The logging mechanism in the above code is implemented using Python's built-in `logging` module.