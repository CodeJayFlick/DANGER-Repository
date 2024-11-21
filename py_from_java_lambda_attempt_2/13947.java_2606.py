Here is the translation of the Java code into Python:

```Python
import unittest
from random import randint

class User:
    def __init__(self, first_name: str, last_name: str, active: bool, email: str):
        self.first_name = first_name
        self.last_name = last_name
        self.active = active
        self.email = email


class UserDto:
    def __init__(self, first_name: str, last_name: str, active: bool, email: str):
        self.first_name = first_name
        self.last_name = last_name
        self.active = active
        self.email = email


def convert_from_entity(user: User) -> UserDto:
    return UserDto(user.first_name, user.last_name, user.active, f"{user.first_name.lower()}{user.last_name.lower()}@whatever.com")


def convert_to_entity(userdto: UserDto) -> User:
    return User(userdto.first_name, userdto.last_name, userdto.active, str(randint(0, 10000000)))


class ConverterTest(unittest.TestCase):
    def setUp(self):
        self.user_converter = {
            'convert_from_entity': lambda x: convert_to_entity(convert_from_entity(x)),
            'convert_from_dto': lambda x: convert_from_entity(convert_to_entity(x))
        }

    def test_conversions_starting_from_domain(self):
        user1 = User("Tom", "Hanks", True, "tom@hanks.com")
        user2 = self.user_converter['convert_from_dto'](self.user_converter['convert_from_entity'](user1))
        self.assertEqual(user1, user2)

    def test_conversions_starting_from	dto(self):
        userdto1 = UserDto("Tom", "Hanks", True, "tom@hanks.com")
        user2 = self.user_converter['convert_from_dto'](self.user_converter['convert_from_entity'](userdto1))
        self.assertEqual(userdto1, user2)

    def test_custom_converter(self):
        converter = {
            'convert': lambda x: User(x.first_name, x.last_name, x.active, f"{x.first_name.lower()}{x.last_name.lower()}@whatever.com"),
            'reverse_convert': lambda x: UserDto(x.first_name, x.last_name, x.active, str(randint(0, 10000000)))
        }
        user1 = User("John", "Doe", False, "12324")
        userdto = converter['convert'](user1)
        self.assertEqual(userdto.email, f"johndoe@whatever.com")

    def test_collection_conversion(self):
        users = [User(f"Camile{i}", f"Tough{i}", i % 2 == 0, f"124sad{i}") for i in range(3)]
        from_dtos = self.user_converter['convert_from_dto'](self.user_converter['convert_from_entity'](users))
        self.assertEqual(users, list(map(lambda x: UserDto(*x), zip(from_dtos))))


if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@Test` annotation. Instead, we use the built-in testing framework called `unittest`.