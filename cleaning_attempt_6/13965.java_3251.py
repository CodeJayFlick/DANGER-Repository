import sqlite3
from typing import Optional

class Customer:
    def __init__(self, id: int, first_name: str, last_name: str):
        self.id = id
        self.first_name = first_name
        self.last_name = last_name


class DbCustomerDao:
    def __init__(self, dataSource: sqlite3.connect):
        self.dataSource = dataSource

    def get_all(self) -> Optional[sqlite3.Cursor]:
        try:
            connection = self.get_connection()
            statement = connection.execute("SELECT * FROM CUSTOMERS")
            return statement
        except Exception as e:
            print(f"Exception thrown {e}")

    def get_by_id(self, id: int) -> Optional[Customer]:
        try:
            connection = self.get_connection()
            statement = connection.execute("SELECT * FROM CUSTOMERS WHERE ID = ?", (id,))
            if statement.fetchone():
                return Customer(*statement.fetchone())
            else:
                return None
        except Exception as e:
            print(f"Exception thrown {e}")

    def add(self, customer: Customer) -> bool:
        try:
            connection = self.get_connection()
            with connection.cursor() as cursor:
                cursor.execute("INSERT INTO CUSTOMERS VALUES (?,?,?)", (customer.id, customer.first_name, customer.last_name))
                return True
        except Exception as e:
            print(f"Exception thrown {e}")

    def update(self, customer: Customer) -> bool:
        try:
            connection = self.get_connection()
            with connection.cursor() as cursor:
                cursor.execute("UPDATE CUSTOMERS SET FNAME = ?, LNAME = ? WHERE ID = ?", (customer.first_name, customer.last_name, customer.id))
                return True
        except Exception as e:
            print(f"Exception thrown {e}")

    def delete(self, customer: Customer) -> bool:
        try:
            connection = self.get_connection()
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM CUSTOMERS WHERE ID = ?", (customer.id,))
                return True
        except Exception as e:
            print(f"Exception thrown {e}")

    def get_connection(self):
        return self.dataSource

