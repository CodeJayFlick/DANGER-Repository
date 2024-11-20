Here is the translation of the Java code into Python:

```Python
class GoToService:
    VALID_GOTO_CHARS = [".", ":", "*"]

    def __init__(self):
        pass

    def go_to(self, loc: 'ProgramLocation') -> bool:
        # Implement this method according to your needs.
        return True  # Replace with actual implementation.

    def go_to(self, loc: 'ProgramLocation', program: 'Program') -> bool:
        # Implement this method according to your needs.
        return self.go_to(loc)

    def go_to(self, navigatable: 'Navigatable', loc: 'ProgramLocation', program: 'Program') -> bool:
        # Implement this method according to your needs.
        return True  # Replace with actual implementation.

    def go_to(self, navigatable: 'Navigatable', program: 'Program', address: 'Address', ref_address: 'Address') -> bool:
        # Implement this method according to your needs.
        return True  # Replace with actual implementation.

    def go_to(self, current_address: 'Address', goTo_address: 'Address') -> bool:
        # Implement this method according to your needs.
        return self.go_to(current_address)

    def go_to(self, navigatable: 'Navigatable', address: 'Address') -> bool:
        # Implement this method according to your needs.
        return True  # Replace with actual implementation.

    def go_to(self, goTo_address: 'Address', program: 'Program') -> bool:
        # Implement this method according to your needs.
        return self.go_to(goTo_address)

    def go_to_external_location(self, external_loc: 'ExternalLocation', check_navigation_option: bool) -> bool:
        # Implement this method according to your needs.
        return True  # Replace with actual implementation.

    def go_to_external_location(self, navigatable: 'Navigatable', external_loc: 'ExternalLocation', 
                                 check_navigation_option: bool) -> bool:
        # Implement this method according to your needs.
        return self.go_to_external_location(external_loc)

    def go_to_query(self, from_addr: 'Address', query_data: object, listener: object, monitor: object) -> bool:
        # Implement this method according to your needs.
        return True  # Replace with actual implementation.

    def get_override_service(self):
        pass

    def set_override_service(self, override: object):
        pass

    def get_default_navigatable(self):
        pass
```

Please note that the Python code does not have direct equivalent of Java's `@ServiceInfo` and other annotations. Also, Python is dynamically typed language so it doesn't require explicit type declarations like in Java.