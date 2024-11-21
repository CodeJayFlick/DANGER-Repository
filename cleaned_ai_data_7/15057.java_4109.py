import unittest
from io import StringIO
import re

class SkyLaunchTest(unittest.TestCase):

    def test_move(self):
        sky_launch = SkyLaunch()
        output_log = get_log_content(lambda: sky_launch.move(1.0, 1.0, 1.0))
        expected_log = "Move to ( 1.0, 1.0, 1.0 )"
        self.assertEqual(output_log, expected_log)

    def test_play_sound(self):
        sky_launch = SkyLaunch()
        output_log = get_log_content(lambda: sky_launch.play_sound("SOUND_NAME", 1))
        expected_log = "Play SOUND_NAME with volume 1"
        self.assertEqual(output_log, expected_log)

    def test_spawn_particles(self):
        sky_launch = SkyLaunch()
        output_log = get_log_content(lambda: sky_launch.spawn_particles("PARTICLE_TYPE", 100))
        expected_log = "Spawn 100 particle with type PARTICLE_TYPE"
        self.assertEqual(output_log, expected_log)

    def test_activate(self):
        sky_launch = SkyLaunch()
        logs = capture_stdout(sky_launch.activate)
        log1 = get_log_content(logs[0])
        expected_log1 = "Move to ( 0.0, 0.0, 20.0 )"
        log2 = get_log_content(logs[1])
        expected_log2 = "Play SKYLAUNCH_SOUND with volume 1"
        log3 = get_log_content(logs[2])
        expected_log3 = "Spawn 100 particle with type SKYLAUNCH_PARTICLE"
        self.assertEqual(len(logs), 3)
        self.assertEqual(log1, expected_log1)
        self.assertEqual(log2, expected_log2)
        self.assertEqual(log3, expected_log3)

    def get_log_content(self, statement):
        log = capture_stdout(statement())
        return re.split(r"-| ", log)[5].strip()

def capture_stdout(func):
    import io
    old_stdout = sys.stdout
    new_stdout = StringIO()
    sys.stdout = new_stdout
    result = func()
    sys.stdout = old_stdout
    return new_stdout.getvalue().splitlines()

if __name__ == '__main__':
    unittest.main()
