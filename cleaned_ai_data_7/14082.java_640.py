class CollisionTest:
    def __init__(self):
        pass

    def get_tested_object(self) -> object:
        raise NotImplementedError("This method must be implemented by subclass")

    def test_collision(self, other: 'GameObject', other_damaged: bool, other_on_fire: bool,
                       this_damaged: bool, this_on_fire: bool) -> None:
        if not isinstance(other, GameObject):
            raise TypeError('other must be an instance of GameObject')
        if self.get_tested_object() is None:
            raise ValueError("getTestedObject should never return 'null'")

        tested = self.get_tested_object()

        tested.collision(other)

        self.test_on_fire(tested, other, this_on_fire)
        self.test_damaged(tested, other, this_damaged)

    def test_on_fire(self, target: 'GameObject', other: 'GameObject', expect_target_on_fire: bool) -> None:
        if not isinstance(target, GameObject):
            raise TypeError('target must be an instance of GameObject')
        if not isinstance(other, GameObject):
            raise TypeError('other must be an instance of GameObject')

        error_message = f"Expected {type(target).__name__} to {'be' if expect_target_on_fire else 'not be'} on fire after colliding with {type(other).__name__}, but it was{'!' * (expect_target_on_fire or not target.is_on_fire())}"
        self.assertEqual(expect_target_on_fire, target.is_on_fire(), error_message)

    def test_damaged(self, target: 'GameObject', other: 'GameObject', expected_damage: bool) -> None:
        if not isinstance(target, GameObject):
            raise TypeError('target must be an instance of GameObject')
        if not isinstance(other, GameObject):
            raise TypeError('other must be an instance of GameObject')

        error_message = f"Expected {type(target).__name__} to {'be' if expected_damage else 'not be'} damaged after colliding with {type(other).__name__}, but it was{'!' * (expected_damage or not target.is_damaged())}"
        self.assertEqual(expected_damage, target.is_damaged(), error_message)
