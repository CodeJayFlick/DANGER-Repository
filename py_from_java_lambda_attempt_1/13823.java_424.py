Here is the translation of the given Java code into Python:

```Python
import logging

class Wizard:
    def __init__(self):
        self.health = 0
        self.agility = 0
        self.wisdom = 0
        self.number_of_played_sounds = 0
        self.number_of_spawned_particles = 0

    @property
    def health(self):
        return self._health

    @health.setter
    def health(self, value):
        self._health = value

    @property
    def agility(self):
        return self._agility

    @agility.setter
    def agility(self, value):
        self._agility = value

    @property
    def wisdom(self):
        return self._wisdom

    @wisdom.setter
    def wisdom(self, value):
        self._wisdom = value

    @property
    def number_of_played_sounds(self):
        return self._number_of_played_sounds

    @number_of_played_sounds.setter
    def number_of_played_sounds(self, value):
        self._number_of_played_sounds = value

    @property
    def number_of_spawned_particles(self):
        return self._number_of_spawned_particles

    @number_of_spawned_particles.setter
    def number_of_spawned_particles(self, value):
        self._number_of_spawned_particles = value

    def play_sound(self):
        logging.info("Playing sound")
        self.number_of_played_sounds += 1

    def spawn_particles(self):
        logging.info("Spawning particles")
        self.number_of_spawned_particles += 1
```

Note: Python does not have a direct equivalent to Java's `@AllArgsConstructor`, `@Setter`, and `@Getter` annotations. The above code uses property decorators (`@property`) to achieve similar functionality.