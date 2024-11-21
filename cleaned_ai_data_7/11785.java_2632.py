class Token:
    def __init__(self):
        self.kind = None
        self.beginLine = 0
        self.beginColumn = 0
        self.endLine = 0
        self.endColumn = 0
        self.image = ''
        self.next = None
        self.specialToken = None

    @property
    def kind(self):
        return self._kind

    @kind.setter
    def kind(self, value):
        self._kind = value

    @property
    def beginLine(self):
        return self._beginLine

    @beginLine.setter
    def beginLine(self, value):
        self._beginLine = value

    @property
    def beginColumn(self):
        return self._beginColumn

    @beginColumn.setter
    def beginColumn(self, value):
        self._beginColumn = value

    @property
    def endLine(self):
        return self._endLine

    @endLine.setter
    def endLine(self, value):
        self._endLine = value

    @property
    def endColumn(self):
        return self._endColumn

    @endColumn.setter
    def endColumn(self, value):
        self._endColumn = value

    @property
    def image(self):
        return self._image

    @image.setter
    def image(self, value):
        self._image = value

    @property
    def next(self):
        return self._next

    @next.setter
    def next(self, value):
        self._next = value

    @property
    def specialToken(self):
        return self._specialToken

    @specialToken.setter
    def specialToken(self, value):
        self._specialToken = value

    def __str__(self):
        return self.image


def new_token(of_kind: int) -> 'Token':
    if of_kind == 0:
        return Token()
