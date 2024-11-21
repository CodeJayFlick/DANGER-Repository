import logging

class BookViewModel:
    def __init__(self):
        self.book_list = []
        self.selected_book = None
        self.book_service = BookService()

    @property
    def selected_book(self):
        return self._selected_book

    @selected_book.setter
    def selected_book(self, value):
        if self._selected_book != value:
            self._selected_book = value
            self.notify_change("selected_book")

    @property
    def book_list(self):
        return self.book_service.load()

    def delete_book(self):
        if self.selected_book is not None:
            self.book_list.remove(self.selected_book)
            self.selected_book = None

class BookService:
    def load(self):
        # TO DO: implement loading books from some data source
        pass

# Example usage:
vm = BookViewModel()
print(vm.book_list)  # []
print(vm.selected_book)  # None

book1 = Book(title="Book 1")
book2 = Book(title="Book 2")

vm.book_service.load()  # assume this sets book_list and selected_book
print(vm.book_list)  # [book1, book2]
print(vm.selected_book)  # book1 or book2 (depending on the load implementation)

# delete a book
vm.delete_book()
print(vm.book_list)  # []
print(vm.selected_book)  # None

class Book:
    def __init__(self, title):
        self.title = title
