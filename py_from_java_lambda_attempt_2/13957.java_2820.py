Here is the translation of the Java code into Python:

```Python
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, BigInteger
from sqlalchemy.ext.hybrid import hybrid_property

Base = declarative_base()

class Author(Base):
    __tablename__ = 'author'
    id = Column(Integer, primary_key=True)
    username = Column(String)
    name = Column(String)
    email = Column(String)

class Book(Base):
    __tablename__ = 'book'
    id = Column(Integer, primary_key=True)
    title = Column(String)
    price = Column(Integer)
    author_id = Column(Integer, ForeignKey('author.id'))

Base.metadata.create_all()

engine = sa.create_engine('sqlite:///cqrs.db')
Session = sessionmaker(bind=engine)

class QueryService:
    def __init__(self):
        self.session = Session()

    def get_author_by_username(self, username):
        try:
            query = self.session.query(Author).filter(Author.username == username)
            author_dto = query.first()
            return author_dto
        except Exception as e:
            print(f"Error: {e}")
            return None

    def get_book(self, title):
        try:
            query = self.session.query(Book).filter(Book.title == title)
            book_dto = query.first()
            return book_dto
        except Exception as e:
            print(f"Error: {e}")
            return None

    def get_author_books(self, username):
        try:
            query = self.session.query(Book).join(Author, Book.author_id == Author.id).filter(Author.username == username)
            books = query.all()
            return books
        except Exception as e:
            print(f"Error: {e}")
            return None

    def get_author_books_count(self, username):
        try:
            query = self.session.query(sa.func.count(Book.title)).join(Author, Book.author_id == Author.id).filter(Author.username == username)
            count = query.first()[0]
            return count
        except Exception as e:
            print(f"Error: {e}")
            return None

    def get_authors_count(self):
        try:
            query = self.session.query(sa.func.count(Author.id))
            count = query.first()[0]
            return count
        except Exception as e:
            print(f"Error: {e}")
            return None


if __name__ == "__main__":
    service = QueryService()
    username = "your_username"
    author_dto = service.get_author_by_username(username)
    book_dto = service.get_book("book_title")
    books = service.get_author_books(username)
    count = service.get_author_books_count(username)
    authors_count = service.get_authors_count()

```

Please note that this code uses SQLAlchemy, a Python SQL toolkit and Object-Relational Mapping (ORM) library.