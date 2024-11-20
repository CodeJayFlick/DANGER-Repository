import unittest


class VirtualMachineTest(unittest.TestCase):

    def test_literal(self):
        bytecode = [LITERAL, 10]
        vm = VirtualMachine()
        vm.execute(bytecode)
        self.assertEqual(1, len(vm.stack))
        self.assertEqual(10, vm.stack.pop())

    def test_set_health(self):
        wizard_number = 0
        bytecode = [LITERAL, wizard_number, LITERAL, 50, SET_HEALTH]
        vm = VirtualMachine()
        vm.execute(bytecode)
        self.assertEqual(50, vm.wizards[wizard_number].health)

    def test_set_agility(self):
        wizard_number = 0
        bytecode = [LITERAL, wizard_number, LITERAL, 50, SET_AGILITY]
        vm = VirtualMachine()
        vm.execute(bytecode)
        self.assertEqual(50, vm.wizards[wizard_number].agility)

    def test_set_wisdom(self):
        wizard_number = 0
        bytecode = [LITERAL, wizard_number, LITERAL, 50, SET_WISDOM]
        vm = VirtualMachine()
        vm.execute(bytecode)
        self.assertEqual(50, vm.wizards[wizard_number].wisdom)

    def test_get_health(self):
        wizard_number = 0
        bytecode = [LITERAL, wizard_number, LITERAL, 50, SET_HEALTH, LITERAL, wizard_number, GET_HEALTH]
        vm = VirtualMachine()
        vm.execute(bytecode)
        self.assertEqual(50, vm.stack.pop())

    def test_play_sound(self):
        wizard_number = 0
        bytecode = [LITERAL, wizard_number, PLAY_SOUND]
        vm = VirtualMachine()
        vm.execute(bytecode)
        self.assertEqual(0, len(vm.stack))
        self.assertEqual(1, vm.wizards[wizard_number].number_of_played_sounds)

    def test_spawn_particles(self):
        wizard_number = 0
        bytecode = [LITERAL, wizard_number, SPAWN_PARTICLES]
        vm = VirtualMachine()
        vm.execute(bytecode)
        self.assertEqual(0, len(vm.stack))
        self.assertEqual(1, vm.wizards[wizard_number].number_of_spawned_particles)

    def test_invalid_instruction(self):
        bytecode = [999]
        with self.assertRaises(IllegalArgumentException):
            vm = VirtualMachine()
            vm.execute(bytecode)


if __name__ == '__main__':
    unittest.main()
