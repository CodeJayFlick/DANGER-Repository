class Captain:
    def __init__(self):
        self.rowing_boat = None

    @property
    def rowing_boat(self):
        return self._rowing_boat

    @rowing_boat.setter
    def rowing_boat(self, value):
        self._rowing_boat = value

    def row(self):
        if self.rowing_boat is not None:
            self.rowing_boat.row()
