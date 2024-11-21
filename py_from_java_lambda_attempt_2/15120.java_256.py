Here is the equivalent Python code:

```Python
class RoomTest:
    def __init__(self):
        self.room = None

    @classmethod
    def setUpClass(cls):
        cls.room = Room(1, "Single", 50, False)

    def test_get_and_set_id(self):
        new_id = 2
        self.room.id = new_id
        assert self.room.id == new_id

    def test_get_and_set_room_type(self):
        new_room_type = "Double"
        self.room.room_type = new_room_type
        assert self.room.room_type == new_room_type

    def test_get_and_set_price(self):
        new_price = 60
        self.room.price = new_price
        assert self.room.price == new_price

    def test_not_equal_with_different_id(self):
        new_id = 2
        other_room = Room(new_id, "Single", 50, False)
        assert not (self.room == other_room) and not hash(self.room) == hash(other_room)

    def test_equals_with_same_object_values(self):
        other_room = Room(1, "Single", 50, False)
        assert self.room == other_room and hash(self.room) == hash(other_room)

    def test_equals_with_same_objects(self):
        assert self.room == self.room
        assert hash(self.room) == hash(self.room)

    @classmethod
    def tearDownClass(cls):
        cls.room = None

class Room:
    def __init__(self, id, room_type, price, booked):
        self.id = id
        self.room_type = room_type
        self.price = price
        self.booked = booked

    def __str__(self):
        return f"Room(id={self.id}, roomType='{self.room_type}', price={self.price}, booked={self.booked})"

if __name__ == "__main__":
    import unittest
    suite = unittest.TestLoader().loadTestsFromTestCase(RoomTest)
    unittest.TextTestRunner(verbosity=2).run(suite)
```

Note: Python does not have a direct equivalent to Java's `@BeforeEach` and `@AfterEach`. Instead, you can use the setup method in your test class. Also, there is no built-in support for asserting that two objects are equal or not equal based on their hash values like JUnit Jupiter provides with its `assertNotEquals` assertion.