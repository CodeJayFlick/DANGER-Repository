Here is the translation of the Java code to Python:

```Python
import logging
from typing import List

logging.basicConfig(level=logging.INFO)

class Person:
    def __init__(self, name: str, surname: str, age: int):
        self.name = name
        self.surname = surname
        self.age = age

def main():
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy import create_engine

    engine = create_engine('sqlite:///test.db', echo=True)
    Session = sessionmaker(bind=engine)

    base = declarative_base()

    class Person(base):
        __tablename__ = 'person'
        id = column(Integer, primary_key=True)
        name = column(String)
        surname = column(String)
        age = column(Integer)

    from sqlalchemy.orm import session

    with Session() as session:
        peter = Person("Peter", "Sagan", 17)
        nasta = Person("Nasta", "Kuzminova", 25)
        john = Person("John", "lawrence", 35)
        terry = Person("Terry", "Law", 36)

        # Add new Person records
        session.add(peter)
        session.add(nasta)
        session.add(john)
        session.add(terry)

        # Count Person records
        logging.info(f"Count Person records: {session.query(Person).count()}")

        # Print all records
        persons = session.query(Person).all()
        for person in persons:
            logging.info(str(person))

        # Update Person
        nasta.name = "Barbora"
        nasta.surname = "Spotakova"
        session.add(nasta)

        result = session.query(Person).filter_by(id=2).first()
        if result is not None:
            logging.info(f"Find by id 2: {result}")

        # Remove record from Person
        session.delete(session.query(Person).get(2))

        # count records
        logging.info(f"Count Person records: {session.query(Person).count()}")

        # find by name
        result = session.query(Person).filter_by(name="John").first()
        if result is not None:
            logging.info(f"Find by John is {result}")

        # find by age
        persons = session.query(Person).filter(20 <= Person.age, 40 >= Person.age)
        for person in persons:
            logging.info(str(person))

if __name__ == "__main__":
    main()
```

Please note that this code uses SQLAlchemy library to interact with the database.