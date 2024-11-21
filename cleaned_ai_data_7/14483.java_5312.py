import random
import logging
from threading import Thread, current_thread

class Feind(Thread):
    def __init__(self, creature, target):
        self.creature = creature
        self.target = target
        self.random = random.Random()
        self.logger = logging.getLogger(__name__)

    def run(self):
        if not self.creature.acquire(self.target):
            try:
                self.fight_for_sword(self.creature, self.target.get_locker(), self.target)
            except KeyboardInterrupt as e:
                self.logger.error(e.message)
                current_thread().interrupt()
        else:
            self.logger.info("{} has acquired the sword!".format(self.target.get_locker().name))

    def fight_for_sword(self, reacher, holder, sword):
        self.logger.info("A duel between {} and {} has been started!".format(reacher.name, holder.name))
        while self.target.is_locked() and reacher.is_alive() and holder.is_alive():
            if random.random() < 0.5:
                reacher.attack(holder)
            else:
                holder.attack(reacher)

        if reacher.is_alive():
            if not reacher.acquire(sword):
                self.fight_for_sword(reacher, sword.get_locker(), sword)
            else:
                self.logger.info("{} has acquired the sword!".format(reacher.name))
