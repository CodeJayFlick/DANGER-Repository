class DefaultLongPropertyMap:
    def __init__(self, name):
        self.lps = LongPropertySet(name)

    def add(self, addr, value):
        if not isinstance(value, int) or not isinstance(addr, int):
            raise TypeError("Value must be an integer and address must be an integer")
        self.lps.put_long(addr, value)

    def get_long(self, addr):
        try:
            return self.lps.get_long(addr)
        except NoValueException as e:
            print(f"No property found at {addr}. Error: {e}")
            raise

    def get_object(self, addr):
        try:
            return long(self.get_long(addr))
        except (NoValueException, TypeError) as e:
            print(f"Error getting object from address {addr}: {e}")
            return None
