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
