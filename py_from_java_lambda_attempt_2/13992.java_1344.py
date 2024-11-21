Here is the translation of the Java code to Python:
```
import logging

class GameEntity:
    def __init__(self, num_entities):
        self.ai_component_manager = AiComponentManager(num_entities)
        self.physics_component_manager = PhysicsComponentManager(num_entities)
        self.render_component_manager = RenderComponentManager(num_entities)

        # Set up logging
        self.logger = logging.getLogger(__name__)
        self.logger.info("Init Game with #Entity: {}".format(num_entities))

    def start(self):
        self.logger.info("Start Game")
        self.ai_component_manager.start()
        self.physics_component_manager.start()
        self.render_component_manager.start()

    def update(self):
        self.logger.info("Update Game Component")

        # Process AI
        self.ai_component_manager.update()

        # Update physics
        self.physics_component_manager.update()

        # Draw to screen
        self.render_component_manager.render()


class AiComponentManager:
    def __init__(self, num_entities):
        pass

    def start(self):
        pass

    def update(self):
        pass


class PhysicsComponentManager:
    def __init__(self, num_entities):
        pass

    def start(self):
        pass

    def update(self):
        pass


class RenderComponentManager:
    def __init__(self, num_entities):
        pass

    def render(self):
        pass
```
Note that I did not implement the `AiComponentManager`, `PhysicsComponentManager`, and `RenderComponentManager` classes in Python as they were not provided with their respective implementations.