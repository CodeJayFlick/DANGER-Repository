Here is the translation of the Java code into Python:

```Python
class PreviousRangeAction:
    def __init__(self, tool: 'PluginTool', name: str, owner: str, nav_options: 'NavigationOptions') -> None:
        self.tool = tool
        self.nav_options = nav_options
        super().__init__(name, owner)
        self.set_enabled(False)

    def action_performed(self, context: 'NavigatableActionContext') -> None:
        address_to_go = self.get_address_to_go(context)
        if address_to_go is not None and isinstance(address_to_go, Address):
            service = self.tool.get_service(GoToService)
            if service is not None:
                service.go_to(context.get_navigatable(), address_to_go)

    def get_address_to_go(self, context: 'NavigatableActionContext') -> Address | None:
        selection = self.get_selection(context)
        current_address = context.get_address()

        iterator = selection.get_address_ranges(current_address, False)
        if not iterator.has_next():
            return current_address

        range = next(iterator)

        if range.contains(current_address):
            start_of_range_address = range.min
            if start_of_range_address != current_address:
                return start_of_range_address

            if not iterator.has_next():
                return current_address

            range = next(iterator)
        else:
            # We are at the top...go to previous range
            if not iterator.has_next():
                return current_address

            range = next(iterator)

        if self.nav_options.is_goto_top_and_bottom_of_range_enabled():
            return range.max
        return range.min

    def is_enabled_for_context(self, context: 'NavigatableActionContext') -> bool:
        address_to_check = context.get_address()
        selection = self.get_selection(context)
        if selection is None or not selection and address_to_check is None:
            return False

        return address_to_check > selection.min

    @abstractmethod
    def get_selection(self, context: 'ProgramLocationActionContext') -> ProgramSelection | None:
        pass


class Address:
    def __init__(self) -> None:
        pass

    def contains(self, other_address: 'Address') -> bool:
        return True  # This is a placeholder method. You should implement the actual logic here.

    @property
    def min(self) -> 'Address':
        return self

    @property
    def max(self) -> 'Address':
        return self


class ProgramSelection:
    def __init__(self, address: Address | None = None) -> None:
        if address is not None and isinstance(address, Address):
            self.address = address
        else:
            self.address = None

    @property
    def min(self) -> 'Address':
        return self.address

    @property
    def max(self) -> 'Address':
        return self.address


class NavigationOptions:
    def __init__(self) -> None:
        pass

    def is_goto_top_and_bottom_of_range_enabled(self) -> bool:
        return True  # This is a placeholder method. You should implement the actual logic here.
```

Please note that this translation assumes some classes and methods from Java, which are not available in Python by default.