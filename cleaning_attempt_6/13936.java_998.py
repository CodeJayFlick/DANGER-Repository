class DependentObject:
    def __init__(self):
        self.data = None

    def set_data(self, data):
        self.data = data

    def get_data(self):
        return self.data


# Example usage:
if __name__ == "__main__":
    obj1 = DependentObject()
    obj2 = "Hello"
    
    # Set the data
    obj1.set_data(obj2)
    
    # Get and print the data
    retrieved_data = obj1.get_data()
    print(retrieved_data)  # Output: Hello
