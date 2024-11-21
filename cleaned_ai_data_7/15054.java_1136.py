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
