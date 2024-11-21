Here is the translation of the Java code to Python:

```Python
import logging

# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class App:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def run_app(self):
        # Block 1: PropertiesFeatureToggleVersion with enabled feature toggle
        properties = {"enhancedWelcome": True}
        service = Service(properties)
        welcome_message = service.get_welcome_message(User("Jamie No Code"))
        print(welcome_message)

        # Block 2: PropertiesFeatureToggleVersion with disabled feature toggle
        turned_off_properties = {"enhancedWelcome": False}
        turned_off_service = Service(turned_off_properties)
        welcome_message_turned_off = turned_off_service.get_welcome_message(User("Jamie No Code"))
        print(welcome_message_turned_off)

        # Block 3: TieredFeatureToggleVersion with two users
        service2 = TieredFeatureToggleVersion()
        paid_user = User("Jamie Coder")
        free_user = User("Alan Defect")

        UserGroup.add_user_to_paid_group(paid_user)
        UserGroup.add_user_to_free_group(free_user)

        welcome_message_paid_user = service2.get_welcome_message(paid_user)
        welcome_message_free_user = service2.get_welcome_message(free_user)
        print(welcome_message_free_user)
        print(welcome_message_paid_user)


if __name__ == "__main__":
    app = App()
    app.run_app()

class User:
    def __init__(self, username):
        self.username = username

class Service:
    def __init__(self, properties=None):
        if properties is None:
            properties = {}
        self.properties = properties

    def get_welcome_message(self, user):
        if "enhancedWelcome" in self.properties and self.properties["enhancedWelcome"]:
            return f"Hello {user.username}!"
        else:
            return "Hello!"

class PropertiesFeatureToggleVersion(Service):
    pass


class TieredFeatureToggleVersion(Service):
    pass

class UserGroup:
    users = []

    @classmethod
    def add_user_to_paid_group(cls, user):
        cls.users.append(user)

    @classmethod
    def add_user_to_free_group(cls, user):
        cls.users.append(user)
```

Please note that Python does not have direct equivalent of Java's `@Slf4j` annotation. The logging functionality is implemented using the built-in `logging` module in this translation.