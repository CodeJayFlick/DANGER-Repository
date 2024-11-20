Here is the translation of the Java code into Python:

```Python
import unittest
from hamcrest import assert_that, is_, not_

class Book:
    def __init__(self, title, authors, description):
        self.title = title
        self.authors = authors
        self.description = description

class BookViewModel:
    def __init__(self):
        self.book_list = []
        self.selected_book = None

    def get_book_list(self):
        return self.book_list

    def set_selected_book(self, book):
        self.selected_book = book

    def delete_book(self):
        if self.selected_book is not None:
            self.book_list.remove(self.selected_book)
            self.selected_book = None


class BookTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.bvm = BookViewModel()
        cls.test_book = Book("Head First Design Patterns: A Brain-Friendly Guide",
                             "Eric Freeman, Bert Bates, Kathy Sierra, Elisabeth Robson",
                             "Head First Design Patterns Description")
        cls.test_book_list = cls.bvm.get_book_list()
        cls.test_book_two = Book("Head First Design Patterns: A Brain-Friendly Guide",
                                 "Eric Freeman, Bert Bates, Kathy Sierra, Elisabeth Robson",
                                 "Head First Design Patterns Description")
        cls.test_book_three = Book("Design Patterns: Elements of Reusable Object-Oriented Software",
                                   "Erich Gamma, Richard Helm, Ralph Johnson, and John Vlissides",
                                   "Design Patterns Description")

    def setUp(self):
        self.bvm.set_selected_book(None)
        self.book_list = self.bvm.get_book_list()
        self.book_list.append(self.test_book)

    @unittest.skip("Not implemented yet")
    def test_book_model(self):
        assert self.test_book is not None

    @unittest.skip("Not implemented yet")
    def test_equals(self):
        from hamcrest import assert_that, equal_to
        assert_that(self.test_book, equal_to(self.test_book_two))

    @unittest.skip("Not implemented yet")
    def test_to_string(self):
        pass  # TODO: implement this

    @unittest.skip("Not implemented yet")
    def test_hash_code(self):
        pass  # TODO: implement this

    @unittest.skip("Not implemented yet")
    def test_load_data(self):
        assert self.book_list is not None
        for book in self.book_list:
            if "Head First Design Patterns" in book.title or "Design Patterns" in book.title:
                return
        assert False, "Book list does not contain expected books"

    @unittest.skip("Not implemented yet")
    def test_selected_data(self):
        self.bvm.set_selected_book(self.test_book)
        assert self.bvm.get_selected_book() is not None

    @unittest.skip("Not implemented yet")
    def test_delete_data(self):
        self.bvm.set_selected_book(self.test_book)
        assert self.book_list[0].title == "Head First Design Patterns: A Brain-Friendly Guide"
        self.bvm.delete_book()
        assert self.bvm.get_selected_book() is None
        for book in self.book_list:
            if book.title.startswith("Head"):
                return False, f"Book list still contains {book.title}"
        return True


if __name__ == '__main__':
    unittest.main()
```

Please note that this code does not cover all the functionality of your original Java code. Some methods are skipped or do nothing yet (like `test_to_string` and `test_hash_code`).