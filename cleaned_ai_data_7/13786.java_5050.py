import logging
from time import sleep
from threading import current_thread

class WashingMachineState:
    ENABLED = 0
    WASHING = 1

class DelayProvider:
    def __init__(self):
        self.delayed_tasks = []

    def execute_after_delay(self, delay_ms, task):
        self.delayed_tasks.append((delay_ms, task))
        sleep(delay_ms / 1000)  # convert milliseconds to seconds
        while self.delayed_tasks and self.delayed_tasks[0][0] == delay_ms:
            _, delayed_task = self.delayed_tasks.pop(0)
            delayed_task()

class WashingMachine:
    def __init__(self, delay_provider=None):
        if delay_provider is None:
            self.delay_provider = DelayProvider()
        else:
            self.delay_provider = delay_provider
        self.washing_machine_state = WashingMachineState.ENABLED

    @property
    def washing_machine_state(self):
        return self._washing_machine_state

    @wasing_machine_state.setter
    def washing_machine_state(self, state):
        self._washing_machine_state = state

    def wash(self):
        logging.info(f"{current_thread().name}: Actual machine state: {self.washing_machine_state}")
        if self.washing_machine_state == WashingMachineState.WASHING:
            logging.error("Cannot wash if the machine has been already washing!")
            return
        self.washing_machine_state = WashingMachineState.WASHING
        logging.info(f"{current_thread().name}: Doing the washing")
        self.delay_provider.execute_after_delay(50, lambda: self.end_of_washing())

    def end_of_washing(self):
        self.washing_machine_state = WashingMachineState.ENABLED
        logging.info(f"Washing completed by thread {current_thread().id}")

if __name__ == "__main__":
    # Example usage:
    delay_provider = DelayProvider()
    washing_machine = WashingMachine(delay_provider)
    washing_machine.wash()  # start the washing process
