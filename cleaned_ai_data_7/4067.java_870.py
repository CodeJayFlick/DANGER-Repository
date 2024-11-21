class LocationReferencesService:
    MENU_GROUP = "References"

    def get_help_location(self):
        # Implement this method in your subclass.
        pass

    def show_references_to_location(self, location: 'ProgramLocation', navigatable: 'Navigatable'):
        if not isinstance(location, ProgramLocation) or not isinstance(navigatable, Navigatable):
            raise TypeError("Invalid type")
        
        # Your implementation here
