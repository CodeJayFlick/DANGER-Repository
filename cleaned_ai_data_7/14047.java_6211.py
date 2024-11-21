import sqlite3
from datetime import date, timedelta

class App:
    H2_DB_URL = "jdbc:sqlite:test.db"
    CREATE_SCHEMA_SQL = """
        CREATE TABLE IF NOT EXISTS customers (
            name TEXT PRIMARY KEY,
            money REAL
        );
        
        CREATE TABLE IF NOT EXISTS products (
            name TEXT PRIMARY KEY,
            price REAL,
            expiration_date DATE
        );
        
        CREATE TABLE IF NOT EXISTS purchases (
            product_name TEXT REFERENCES products(name),
            customer_name TEXT REFERENCES customers(name)
        );"""

    DELETE_SCHEMA_SQL = """
        DROP TABLE IF EXISTS customers;
        DROP TABLE IF EXISTS purchases;
        DROP TABLE IF EXISTS products;"""

class Customer:
    def __init__(self, name):
        self.name = name
        self.money = 30.0

    @classmethod
    def builder(cls):
        return cls(None)

    def save(self):
        pass

    def show_balance(self):
        print(f"Customer {self.name} has ${self.money:.2f}")

    def show_purchases(self):
        print("Purchases:")
        # TO DO: implement this method to display purchases
        pass

    def buy_product(self, product):
        if self.money >= product.price:
            self.money -= product.price
            return f"Customer {self.name} bought {product.name}"
        else:
            return "Not enough money"

    def return_product(self, product):
        self.money += product.price
        return f"Customer {self.name} returned {product.name}"

class Product:
    def __init__(self, name, price, expiration_date):
        self.name = name
        self.price = price
        self.expiration_date = expiration_date

    @classmethod
    def builder(cls):
        return cls(None)

def create_schema():
    conn = sqlite3.connect("test.db")
    c = conn.cursor()
    c.execute(App.CREATE_SCHEMA_SQL)
    conn.commit()
    conn.close()

def delete_schema():
    conn = sqlite3.connect("test.db")
    c = conn.cursor()
    c.execute(App.DELETE_SCHEMA_SQL)
    conn.commit()
    conn.close()

if __name__ == "__main__":
    create_schema()
    customer_dao = CustomerDaoImpl()
    
    tom = Customer.builder().name("Tom").money(30.0).build()
    tom.save()

    product_dao = ProductDaoImpl()

    eggs = Product.builder().name("Eggs").price(10.00).expiration_date(date.today() + timedelta(days=7)).build()
    butter = Product.builder().name("Butter").price(20.00).expiration_date(date.today() + timedelta(days=9)).build()
    cheese = Product.builder().name("Cheese").price(25.0).expiration_date(date.today() + timedelta(days=2)).build()

    eggs.save()
    butter.save()
    cheese.save()

    tom.show_balance()
    print(tom.name, "has made the following purchases:")
    
    tom.buy_product(eggs)
    tom.show_balance()
    
    tom.buy_product(butter)
    tom.show_balance()
    
    result = tom.buy_product(cheese)
    if not result:
        print("Not enough money")
    else:
        print(result)

    tom.return_product(butter)
    tom.show_balance()

    result = tom.buy_product(cheese)
    if not result:
        print("Product expired or no longer available")
    else:
        print(result)

    tom.save()
    
    tom.show_balance()
    print(tom.name, "has made the following purchases:")
