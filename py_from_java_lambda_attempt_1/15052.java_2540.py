Here is the translation of the Java code to Python:

```Python
import logging

class GroundDive:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def activate(self):
        self.move(0, 0, -20)
        self.play_sound("GROUNDDIVE_SOUND", 5)
        self.spawn_particles("GROUNDDIVE_PARTICLE", 20)

    # Assume these are methods in another class
    def move(self, x, y, z):
        pass

    def play_sound(self, sound_name, duration):
        pass

    def spawn_particles(self, particle_type, count):
        pass


# Usage:
gd = GroundDive()
gd.activate()
```

Note that Python does not have direct equivalents to Java's `package`, `import org.slf4j.LoggerFactory;` or the specific logging framework used in the original code. The equivalent of these is achieved through Python's built-in `logging` module and by using a logger name (`__name__`) for the current class.

Also, note that I've assumed the methods `move`, `play_sound`, and `spawn_particles` are defined elsewhere (e.g., in another class).