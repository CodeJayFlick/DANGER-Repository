Here is the translation of the Java code into Python:

```Python
class Meteoroid:
    def __init__(self, left: int, top: int, right: int, bottom: int):
        self.left = left
        self.top = top
        self.right = right
        self.bottom = bottom
        self.is_on_fire = False
        self.is_damaged = False

    def get_left(self) -> int:
        return self.left

    def get_top(self) -> int:
        return self.top

    def get_right(self) -> int:
        return self.right

    def get_bottom(self) -> int:
        return self.bottom

    def is_on_fire(self) -> bool:
        return self.is_on_fire

    def is_damaged(self) -> bool:
        return self.is_damaged

    def __str__(self):
        return f"Meteoroid at [{self.left},{self.top},{self.right},{self.bottom}] damaged={self.is_damaged} onFire={self.is_on_fire}"


class TestMeteoroid(unittest.TestCase):

    def test_constructor(self):
        meteoroid = Meteoroid(1, 2, 3, 4)
        self.assertEqual(meteoroid.get_left(), 1)
        self.assertEqual(meteoroid.get_top(), 2)
        self.assertEqual(meteoroid.get_right(), 3)
        self.assertEqual(meteoroid.get_bottom(), 4)
        self.assertFalse(meteoroid.is_on_fire())
        self.assertFalse(meteoroid.is_damaged())

    def test_collide_flaming_asteroid(self):
        asteroid = FlamingAsteroid(1, 1, 3, 4)
        test_collision(meteoroid=meteoroid, asteroid=asteroid, on_fire=True, damaged=False)

    def test_collide_meteoroid(self):
        meteoroid2 = Meteoroid(1, 1, 3, 4)
        test_collision(meteoroid=meteoroid, asteroid=meteoroid2, on_fire=False, damaged=False)

    def test_collide_space_station_iss(self):
        iss = SpaceStationIss(1, 1, 3, 4)
        test_collision(meteoroid=meteoroid, asteroid=iss, on_fire=True, damaged=False)

    def test_collide_space_station_mir(self):
        mir = SpaceStationMir(1, 1, 3, 4)
        test_collision(meteoroid=meteoroid, asteroid=mir, on_fire=True, damaged=False)


if __name__ == '__main__':
    unittest.main()
```

Please note that the `FlamingAsteroid`, `SpaceStationIss` and `SpaceStationMir` classes are not defined in this code. You would need to define these classes or replace them with actual objects for which you want to test collisions.