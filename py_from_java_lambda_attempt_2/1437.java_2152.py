Here's the translation of the Java interface into a Python class:

```Python
class PtySession:
    def wait_exited(self):
        # Implement this method as needed.
        pass  # Return an integer status code if applicable.

    def destroy_forcibly(self):
        # Implement this method to terminate the session (leader and descendants).
        pass  # Release local resources used in maintaining and controlling the remote session, or release remote resources consumed by this session.
```

Note that Python does not have direct support for interfaces like Java. Instead, we can use abstract classes with pure virtual methods as a substitute.