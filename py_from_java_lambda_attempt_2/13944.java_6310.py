Here is the translation of the Java code to Python:
```
# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class UserConverter:
    def __init__(self):
        pass

    @staticmethod
    def convert_to_dto(user: 'User') -> 'UserDto':
        return UserDto(
            user.first_name,
            user.last_name,
            user.is_active,
            user.user_id
        )

    @staticmethod
    def convert_to_entity(dto: 'UserDto') -> 'User':
        return User(
            dto.first_name,
            dto.last_name,
            dto.is_active,
            dto.email
        )
```
Note that I've used Python's type hints to indicate the types of the `convert_to_dto` and `convert_to_entity` methods, but these are not enforced at runtime. Also, I've assumed that there is a `UserDto` class with attributes `first_name`, `last_name`, `is_active`, and `email`, as well as a `User` class with similar attributes.