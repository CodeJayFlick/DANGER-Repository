import random
import time
import logging

class World:
    def __init__(self):
        self.entities = []
        self.is_running = False

    @staticmethod
    def game_loop(self):
        while self.is_running:
            self.process_input()
            self.update()
            self.render()

    def process_input(self):
        lag = random.randint(50, 250)
        time.sleep(lag)

    def update(self):
        for entity in self.entities:
            entity.update()

    def render(self):
        pass

    def run(self):
        logging.info("Start game.")
        self.is_running = True
        thread = threading.Thread(target=self.game_loop, args=(self,))
        thread.start()

    def stop(self):
        logging.info("Stop game.")
        self.is_running = False

    def add_entity(self, entity):
        self.entities.append(entity)

if __name__ == "__main__":
    world = World()
    # Add entities to the world
    for _ in range(10):
        world.add_entity(Entity())  # Replace Entity() with your actual class
    world.run()

class Entity:
    def update(self):
        pass

# You can add more methods and attributes as needed.
