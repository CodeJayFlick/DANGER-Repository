import logging
from queue import Queue
import threading

class ActiveCreature:
    def __init__(self, name):
        self.name = name
        self.status = 0
        self.requests = Queue()
        self.thread = threading.Thread(target=self.run)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def run(self):
        infinite = True
        while infinite:
            try:
                request = self.requests.get()
                request()

            except KeyboardInterrupt as e:
                if self.status != 0:
                    self.logger.error("Thread was interrupted. --> {}", str(e))
                infinite = False

    def eat(self):
        self.requests.put(lambda: (
            self.logger.info("{} is eating!".format(self.name)),
            self.logger.info("{} has finished eating!".format(self.name))
        ))

    def roam(self):
        self.requests.put(lambda:
            self.logger.info("{} has started to roam in the wastelands.".format(self.name)
        )
        )

    def name(self):
        return self.name

    def kill(self, status):
        if status != 0:
            self.logger.error("Thread is being killed.")
        self.status = status
        self.thread.interrupt()

    def get_status(self):
        return self.status


# Example usage:

if __name__ == "__main__":
    creature = ActiveCreature("My Creature")
    try:
        creature.eat()
        creature.roam()
    except KeyboardInterrupt as e:
        print(f"Thread interrupted. --> {str(e)}")

