Here's your Java code translated into Python:

```Python
import unittest
from threading import sleep


class AudioTest(unittest.TestCase):

    def setUp(self):
        self.audio = None

    def test_play_sound(self):
        try:
            from audio_service import get_audio_stream
            self.audio.play_sound(get_audio_stream('./etc/Bass-Drum-1.wav'), -10.0)
            self.assertTrue(self.audio.is_service_running())
            sleep(5)

            self.audio.stop_service()
            self.assertFalse(self.audio.is_service_running())

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_queue(self):
        try:
            from audio_service import get_audio_stream
            for _ in range(3):
                self.audio.play_sound(get_audio_stream('./etc/Bass-Drum-1.aif'), -10.0)
            self.assertTrue(len(self.audio.get_pending_audio()) > 0)

            self.assertTrue(self.audio.is_service_running())
            sleep(10)

            self.audio.stop_service()
            self.assertFalse(self.audio.is_service_running())

        except Exception as e:
            print(f"An error occurred: {e}")


if __name__ == '__main__':
    unittest.main()
```

Please note that this code assumes you have a Python module named `audio_service` with functions like `get_audio_stream`, `play_sound`, and others. You would need to implement these functions in your own audio service class.

Also, the equivalent of Java's `@BeforeEach` is Python's `setUp`. The equivalent of Java's `@Test` is Python's test method (like `test_play_sound`).