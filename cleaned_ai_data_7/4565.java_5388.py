class ViewService:
    def __init__(self):
        pass

    # Add a view that corresponds to the given program location.
    def add_to_view(self, loc: 'ProgramLocation') -> 'AddressSetView':
        return AddressSetView()

    # Get the current view.
    def get_current_view(self) -> 'AddressSetView':
        return AddressSetView()
