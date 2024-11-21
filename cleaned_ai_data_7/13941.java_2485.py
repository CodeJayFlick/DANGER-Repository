import logging

class User:
    def __init__(self, name: str, email: str, active: bool):
        self.name = name
        self.email = email
        self.active = active


class UserDto:
    def __init__(self, name: str, email: str, active: bool, password: str):
        self.name = name
        self.email = email
        self.active = active
        self.password = password

def convert_from_dto(user_dto: UserDto) -> User:
    return User(name=user_dto.name, email=user_dto.email, active=user_dto.active)


def create_from_entities(users: list[User]) -> list[UserDto]:
    user_dtos = []
    for user in users:
        user_dtos.append(UserDto(user.name, user.email, user.active, "whatever"))
    return user_dtos


logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    logging.info("Program started")

    user_converter = UserConverter()

    dto_user = UserDto("John", "Doe", True, "whatever@wherever.com")
    user = convert_from_dto(dto_user)
    logging.info(f"Entity converted from DTO: {user}")

    users = [User("Camile", "Tough", False, "124sad"),
             User("Marti", "Luther", True, "42309fd"),
             User("Kate", "Smith", True, "if0243")]

    logging.info("Domain entities:")
    for user in users:
        logging.info(str(user))

    logging.info("DTO entities converted from domain:")
    dto_entities = create_from_entities(users)
    for user_dto in dto_entities:
        logging.info(str(user_dto))
