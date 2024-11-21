class HelpService:
    DUMMY_HELP_SET_NAME = "Dummy_HelpSet.hs"

    def show_help(self, help_object: object, info_only: bool, parent_component: 'Component') -> None:
        pass  # Implement this method

    def show_help_url(self, url: str) -> None:
        pass  # Implement this method

    def exclude_from_help(self, help_object: object) -> None:
        self.excluded_objects.add(help_object)

    @property
    def excluded_objects(self):
        if not hasattr(self, '_excluded_objects'):
            self._excluded_objects = set()
        return self._excluded_objects

    def is_excluded_from_help(self, help_object: object) -> bool:
        return help_object in self.excluded_objects

    def register_help(self, help_object: object, help_location: 'HelpLocation') -> None:
        pass  # Implement this method

    def clear_help(self, help_object: object) -> None:
        if hasattr(self, '_help_locations'):
            del self._help_locations[help_object]

    @property
    def _help_locations(self):
        if not hasattr(self, '_help_locations'):
            self._help_locations = {}
        return self._help_locations

    def get_help_location(self, help_object: object) -> 'HelpLocation':
        return self._help_locations.get(help_object)

    def help_exists(self) -> bool:
        pass  # Implement this method
