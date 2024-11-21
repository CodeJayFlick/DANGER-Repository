Here is the translation of the given Java code into Python:

```Python
class SpaceStationMir:
    def __init__(self, left: int, top: int, right: int, bottom: int):
        self.left = left
        self.top = top
        self.right = right
        self.bottom = bottom

    def is_on_fire(self) -> bool:
        return False

    def is_damaged(self) -> bool:
        return False

    def __str__(self) -> str:
        return f"SpaceStationMir at [{self.left},{self.top},{self.right},{self.bottom}] damaged=False onFire=False"


class Test(unittest.TestCase):
    def setUp(self):
        self.mir = SpaceStationMir(1, 2, 3, 4)

    def test_constructor(self):
        self.assertEqual(self.mir.left, 1)
        self.assertEqual(self.mir.top, 2)
        self.assertEqual(self.mir.right, 3)
        self.assertEqual(self.mir.bottom, 4)
        self.assertFalse(self.mir.is_on_fire())
        self.assertFalse(self.mir.is_damaged())
        self.assertEqual(str(self.mir), "SpaceStationMir at [1,2,3,4] damaged=False onFire=False")

    def test_collide_flaming_asteroid(self):
        asteroid = FlamingAsteroid(1, 1, 3, 4)
        self.test_collision(asteroid, False, True, False, False)

    def test_collide_meteoroid(self):
        meteoroid = Meteoroid(1, 1, 3, 4)
        self.test_collision(meteoroid, False, False, False, False)

    def test_collide_space_station_iss(self):
        iss = SpaceStationIss(1, 1, 3, 4)
        self.test_collision(iss, True, False, False, False)

    def test_collide_space_station_mir(self):
        mir = SpaceStationMir(1, 1, 3, 4)
        self.test_collision(mir, True, False, False, False)

    def test_collision(self, other: 'SpaceObject', is_damaged: bool, on_fire: bool, damaged: bool, fire: bool):
        if isinstance(other, FlamingAsteroid):
            self.assertTrue(is_damaged)
            self.assertTrue(on_fire)
        elif isinstance(other, Meteoroid):
            pass  # No damage or fire
        elif isinstance(other, SpaceStationIss) or isinstance(other, SpaceStationMir):
            self.assertTrue(damaged)
            self.assertFalse(fire)


if __name__ == '__main__':
    unittest.main()
```

Please note that the Python code above assumes you have `unittest` and other classes (`FlamingAsteroid`, `Meteoroid`, `SpaceStationIss`) defined elsewhere in your project.