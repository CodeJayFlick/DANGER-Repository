import unittest
from ghidra.dbg.target import *
from ghidra.dbg.test import *

class AbstractModelForGdbLauncherTest(unittest.TestCase):

    def get_launch_specimen(self):
        return GdbLinuxSpecimen.PRINT

    def get_expected_launcher_parameters(self):
        return GdbModelTargetInferior.PARAMETERS

    def assert_environment(self, environment):
        self.assertEqual("i386: x86-64", environment.get_architecture())
        self.assertEqual("GNU/Linux", environment.get_operating_system())
        self.assertEqual("little", environment.get_endian())
        self.assertTrue(environment.get_debugger().lower().contains("gdb"))

    def get_launch_stripped_specimen(self):
        return GdbLinuxSpecimen.SPIN_STRIPPED

    @unittest.skip
    def test_launch_stripped_then_interrupt(self):

        # m.build()
        
        listener = ProcessCreatedDebugModelListener()

        specimen = self.get_launch_stripped_specimen()
        launcher = find_launcher()
        wait_acc(launcher)
        wait_on(launcher.launch(specimen.get_launcher_args()))

        # System.err.println("Launched")

        interruptible = suitable(TargetInterruptible, launcher.path)
        time.sleep(1)  # HACK
        wait_on(interruptible.interrupt())

        wait_on(listener.observed_created)

    def test_launch_stripped_then_interrupt(self):
        pass

if __name__ == "__main__":
    unittest.main()
