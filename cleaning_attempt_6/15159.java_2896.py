class Book:
    def __init__(self):
        self.id = None
        self.title = ""
        self.author = ""
        self.version = 0

    @classmethod
    def from_book(cls, book: 'Book'):
        return cls(id=book.id, title=book.title, author=book.author, version=book.version)

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value

    @property
    def title(self):
        return self._title

    @title.setter
    def title(self, value):
        self._title = value

    @property
    def author(self):
        return self._author

    @author.setter
    def author(self, value):
        self._author = value

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, value):
        self._version = value
