Here is the translation of the Java code to Python:
```
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
```
Note that I used the `@classmethod` decorator to define a class method `from_book`, which is equivalent to the Java constructor. I also used Python's property syntax (`@property`) and setter/getter methods to implement getter/setter behavior for each attribute.

Also, in Python, we don't need to explicitly declare types like we do in Java, so you won't see any type declarations (e.g., `long`, `String`) in the code.