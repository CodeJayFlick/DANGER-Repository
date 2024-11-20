class BookRepository:
    def __init__(self):
        self.collection = {}

    def add(self, book: 'Book') -> None:
        if book.id in self.collection:
            raise BookDuplicateException(f"Duplicated book with id: {book.id}")
        self.collection[book.id] = {'id': book.id, **vars(book)}

    def update(self, book: 'Book') -> None:
        if book.id not in self.collection:
            raise BookNotFoundException(f"Not found book with id: {book.id}")

        latest_book = self.collection[book.id]
        if book.version != latest_book['version']:
            raise VersionMismatchException(
                f"Tried to update stale version {book.version} while actual version is {latest_book['version']}"
            )

        book.set_version(book.get_version() + 1)
        self.collection[book.id] = {'id': book.id, **vars(book)}

    def get(self, book_id: int) -> 'Book':
        if book_id not in self.collection:
            raise BookNotFoundException(f"Not found book with id: {book_id}")

        return Book(**self.collection[book_id])

class BookDuplicateException(Exception):
    pass

class BookNotFoundException(Exception):
    pass

class VersionMismatchException(Exception):
    pass
