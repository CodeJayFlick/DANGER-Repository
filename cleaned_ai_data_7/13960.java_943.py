import logging
from typing import List

class Customer:
    def __init__(self, id: int, first_name: str, last_name: str):
        self.id = id
        self.first_name = first_name
        self.last_name = last_name

    def set_first_name(self, name: str) -> None:
        self.first_name = name

    def set_last_name(self, name: str) -> None:
        self.last_name = name

    def __str__(self) -> str:
        return f"Customer(id={self.id}, first_name='{self.first_name}', last_name='{self.last_name}')"

class CustomerDao:
    def __init__(self):
        pass

    def add(self, customer: 'Customer') -> None:
        # Add the customer to database
        logging.info(f"Added {customer}")

    def get_all(self) -> List['Customer']:
        # Return all customers from database
        return [Customer(1, "Adam", "Adamson"), Customer(2, "Bob", "Bobson"), Customer(3, "Carl", "Carlson")]

    def get_by_id(self, id: int) -> 'Customer':
        # Get customer by ID from database
        if id == 2:
            return Customer(id=4, first_name="Dan", last_name="Danson")
        else:
            return None

    def update(self, customer: 'Customer') -> None:
        # Update the customer in database
        logging.info(f"Updated {customer}")

    def delete(self, customer: 'Customer') -> None:
        # Delete the customer from database
        logging.info(f"Deleted {customer}")

def create_data_source() -> dict:
    return {"url": "jdbc:h2:~/dao"}

def perform_operations_using(customer_dao: CustomerDao) -> None:
    add_customers(customer_dao)
    logging.info("Added customers")
    
    for customer in customer_dao.get_all():
        logging.info(str(customer))

    customer = customer_dao.get_by_id(2)
    if customer is not None:
        customer.set_first_name("Daniel")
        customer.set_last_name("Danielson")

    customer_dao.add(Customer(id=4, first_name="Dan", last_name="Danson"))
    logging.info(f"Added {customer_dao.get_all()}")

    for customer in customer_dao.get_all():
        if str(customer) == "Customer(id=2, first_name='Bob', last_name='Bobson')":
            customer.set_first_name("Daniel")
            customer.set_last_name("Danielson")
        logging.info(str(customer))

    customer_dao.delete(Customer(id=4, first_name="Dan", last_name="Danson"))
    logging.info(f"Deleted {customer_dao.get_all()}")

def add_customers(customer_dao: CustomerDao) -> None:
    for _ in range(3):
        customer = Customer(id=len(list(range(1, 5))), "Adam", "Adamson")
        customer_dao.add(customer)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    create_data_source()
    perform_operations_using(CustomerDao())
