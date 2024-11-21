class CommandService:
    def __init__(self):
        self.session_factory = HibernateUtil.get_session_factory()

    def get_author_by_username(self, username):
        author = None
        try:
            session = self.session_factory.open_session()
            query = session.query(Author).filter(Author.username == username)
            author = query.first()
        except Exception as e:
            print(f"Error: {e}")
        if author is None:
            raise ValueError("Author {} doesn't exist!".format(username))
        return author

    def get_book_by_title(self, title):
        book = None
        try:
            session = self.session_factory.open_session()
            query = session.query(Book).filter(Book.title == title)
            book = query.first()
        except Exception as e:
            print(f"Error: {e}")
        if book is None:
            raise ValueError("Book {} doesn't exist!".format(title))
        return book

    def author_created(self, username, name, email):
        try:
            session = self.session_factory.open_session()
            session.begin_transaction()
            author = Author(username=username, name=name, email=email)
            session.add(author)
            session.commit()
        except Exception as e:
            print(f"Error: {e}")

    def book_added_to_author(self, title, price, username):
        try:
            session = self.session_factory.open_session()
            session.begin_transaction()
            author = self.get_author_by_username(username)
            book = Book(title=title, price=price, author=author)
            session.add(book)
            session.commit()
        except Exception as e:
            print(f"Error: {e}")

    def author_name_updated(self, username, name):
        try:
            session = self.session_factory.open_session()
            session.begin_transaction()
            author = self.get_author_by_username(username)
            author.name = name
            session.update(author)
            session.commit()
        except Exception as e:
            print(f"Error: {e}")

    def author_username_updated(self, old_username, new_username):
        try:
            session = self.session_factory.open_session()
            session.begin_transaction()
            author = self.get_author_by_username(old_username)
            author.username = new_username
            session.update(author)
            session.commit()
        except Exception as e:
            print(f"Error: {e}")

    def author_email_updated(self, username, email):
        try:
            session = self.session_factory.open_session()
            session.begin_transaction()
            author = self.get_author_by_username(username)
            author.email = email
            session.update(author)
            session.commit()
        except Exception as e:
            print(f"Error: {e}")

    def book_title_updated(self, old_title, new_title):
        try:
            session = self.session_factory.open_session()
            session.begin_transaction()
            book = self.get_book_by_title(old_title)
            book.title = new_title
            session.update(book)
            session.commit()
        except Exception as e:
            print(f"Error: {e}")

    def book_price_updated(self, title, price):
        try:
            session = self.session_factory.open_session()
            session.begin_transaction()
            book = self.get_book_by_title(title)
            book.price = price
            session.update(book)
            session.commit()
        except Exception as e:
            print(f"Error: {e}")
