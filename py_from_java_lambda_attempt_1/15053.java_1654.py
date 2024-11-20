Here is the translation of the given Java code into Python:

```Python
import logging

class SkyLaunch:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def activate(self):
        # move(0, 0, 20) - This line doesn't have a direct equivalent in Python.
        # Assuming it's some kind of animation or movement. You would need to implement this yourself using a library like Pygame.

        from playsound import playsound
        playsound('SKYLAUNCH_SOUND.mp3', False)

        # spawnParticles("SKYLAUNCH_PARTICLE", 100) - This line doesn't have a direct equivalent in Python.
        # Assuming it's some kind of particle effect. You would need to implement this yourself using a library like Pygame.

# Usage
sky_launch = SkyLaunch()
sky_launch.activate()
```

Please note that the `move`, `playSound` and `spawnParticles` methods are not directly translatable into Python, as they seem to be specific to Java or other languages. You would need to implement these yourself using a library like Pygame for graphics and sound effects.

Also, this code doesn't include any error handling which is generally good practice in programming.