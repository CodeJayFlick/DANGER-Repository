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
