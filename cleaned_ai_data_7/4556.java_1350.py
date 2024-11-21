class NavigationHistoryService:
    def __init__(self):
        self.history = []

    def next(self, navigatable: 'Navigatable'):
        pass  # implement this method in your subclass

    def previous(self, navigatable: 'Navigatable'):
        pass  # implement this method in your subclass

    def go_next(self, location_memento: LocationMemento):
        if self.history:
            current_index = self.history.index(location_memento)
            next_location = self.history[current_index + 1]
            return next_location
        else:
            return None

    def go_previous(self, location_memento: LocationMemento):
        if self.history:
            current_index = self.history.index(location_memento)
            previous_location = self.history[max(0, current_index - 1)]
            return previous_location
        else:
            return None

    def next_function(self, navigatable: 'Navigatable'):
        pass  # implement this method in your subclass

    def previous_function(self, navigatable: 'Navigatable'):
        pass  # implement this method in your subclass

    def get_previous_locations(self, navigatable: 'Navigatable') -> list:
        return self.history[:]

    def get_next_locations(self, navigatable: 'Navigatable') -> list:
        if not self.history:
            return []
        else:
            return [self.history[-1]]

    def has_next(self, navigatable: 'Navigatable'):
        return bool(len(self.get_next_locations(navigatable)) > 0)

    def has_previous(self, navigatable: 'Navigatable'):
        return bool(len(self.get_previous_locations(navigatable)) > 0)

    def has_next_function(self, navigatable: 'Navigatable') -> bool:
        pass  # implement this method in your subclass

    def has_previous_function(self, navigatable: 'Navigatable') -> bool:
        pass  # implement this method in your subclass

    def add_new_location(self, location_memento):
        self.history.append(location_memento)

    def clear(self, navigatable: 'Navigatable'):
        self.history = []
