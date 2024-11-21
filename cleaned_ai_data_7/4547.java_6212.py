class GoToOverrideService:
    def get_override_component(self):
        # implement this method in your subclass
        pass

    def go_to(self, query_input: str) -> 'ProgramLocation':
        # implement this method in your subclass
        pass

    def go_to(self, goto_address: 'Address') -> 'ProgramLocation':
        # implement this method in your subclass
        pass


class ProgramLocation:
    pass  # you need to define the class or interface for Address and ProgramLocation


# example usage:

class MyGoToOverrideService(GoToOverrideService):
    def get_override_component(self) -> JComponent:
        return None

    def go_to(self, query_input: str) -> 'ProgramLocation':
        pass  # implement this method in your subclass
        return None

    def go_to(self, goto_address: 'Address') -> 'ProgramLocation':
        pass  # implement this method in your subclass
        return None


my_service = MyGoToOverrideService()
print(my_service.get_override_component())
