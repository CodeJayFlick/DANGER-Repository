class FunctionAssociationContext:
    def get_selected_source_function(self):
        # Implement this method in your subclass
        pass

    def get_selection_destination_function(self):
        # Implement this method in your subclass
        pass

    def get_existing_match(self):
        # Implement this method in your subclass
        return None  # Default value if no match exists

    def can_create_match(self):
        # Implement this method in your subclass
        return False  # Default value, assume a new match cannot be created
