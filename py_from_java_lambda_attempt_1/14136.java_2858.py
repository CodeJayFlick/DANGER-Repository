Here is the translation of the Java code to Python:

```Python
class App:
    def __init__(self):
        pass

def main():
    class UserCreatedEvent:  # equivalent to a Java event
        pass

    class UserUpdatedEvent:  # equivalent to a Java event
        pass

    class EventDispatcher:  # equivalent to the Java dispatcher
        def register_handler(self, event_class, handler):
            pass

        def dispatch(self, event):
            if isinstance(event, UserCreatedEvent):  # check for specific events
                print("User created")
            elif isinstance(event, UserUpdatedEvent):
                print("User updated")

    class User:
        def __init__(self, name):
            self.name = name

    dispatcher = EventDispatcher()
    user_created_handler = lambda event: print(f"Handling {event.__class__.__name__} - User Created")  # equivalent to the Java handler
    user_updated_handler = lambda event: print(f"Handling {event.__class__.__name__} - User Updated")

    dispatcher.register_handler(UserCreatedEvent, user_created_handler)
    dispatcher.register_handler(UserUpdatedEvent, user_updated_handler)

    user = User("iluwatar")
    dispatcher.dispatch(UserCreatedEvent(user))
    dispatcher.dispatch(UserUpdatedEvent(user))

if __name__ == "__main__":
    main()
```

Please note that Python does not have direct equivalent to Java's event-driven architecture. The above code is a simple translation of the provided Java code and may need further modifications based on your specific requirements.