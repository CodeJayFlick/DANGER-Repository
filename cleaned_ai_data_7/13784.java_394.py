import threading
import time
import logging

logging.basicConfig(level=logging.ERROR)

class WashingMachine:
    def __init__(self):
        self.state = "ENABLED"

    def wash(self):
        if self.state == "WASHING":
            return  # Balking: don't do anything when already washing
        elif self.state == "ENABLED":
            self.state = "WASHING"
            print("Machine is now WASHING")
        else:
            raise ValueError(f"Invalid state {self.state}")

    def __str__(self):
        return f"Washing Machine ({self.state})"

def main():
    washing_machine = WashingMachine()
    threads = []

    for i in range(3):
        thread = threading.Thread(target=washing_machine.wash)
        thread.start()
        threads.append(thread)

    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
