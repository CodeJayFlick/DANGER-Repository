Here is the translation of the given Java code into Python:

```Python
class Superpower:
    def __init__(self):
        self.logger = None

    def activate(self):
        pass  # Subclasses should implement this method.

    def move(self, x: float, y: float, z: float) -> None:
        if self.logger is not None:
            print(f"Move to ({x}, {y}, {z})")

    def play_sound(self, sound_name: str, volume: int) -> None:
        if self.logger is not None:
            print(f"Play {sound_name} with volume {volume}")

    def spawn_particles(self, particle_type: str, count: int) -> None:
        if self.logger is not None:
            print(f"Spawn {count} particles of type {particle_type}")
```

Note that Python does not have a direct equivalent to Java's `abstract` keyword. Instead, we define the methods in an abstract class as having no implementation (`pass`) and expect subclasses to implement them.

Also note that Python is dynamically typed, so there is no need for explicit type declarations like `double`, `String`, etc., which are present in the original Java code.