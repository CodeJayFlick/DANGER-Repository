import time
import logging

# Set up logging
logging.basicConfig(level=logging.ERROR)

class App:
    GAME_RUNNING_TIME = 2000

    def main(self):
        try:
            world = World()
            skeleton1 = Skeleton(1, 10)
            skeleton2 = Skeleton(2, 70)
            statue = Statue(3, 20)
            world.add_entity(skeleton1)
            world.add_entity(skeleton2)
            world.add_entity(statue)
            world.run()
            time.sleep(self.GAME_RUNNING_TIME)
            world.stop()

        except KeyboardInterrupt:
            logging.error("Interrupted")

class World:
    def __init__(self):
        self.entities = []

    def add_entity(self, entity):
        self.entities.append(entity)

    def run(self):
        for _ in range(2000):  # Simulate game running
            for entity in self.entities:
                entity.update()

    def stop(self):
        pass

class Skeleton:
    def __init__(self, id, health):
        self.id = id
        self.health = health

    def update(self):
        print(f"Skeleton {self.id} is updating...")

class Statue:
    def __init__(self, id, strength):
        self.id = id
        self.strength = strength

    def update(self):
        print(f"Statue {self.id} is updating...")
