class Quad(T1, T2, T3, T4):
    def __init__(self, first: T1, second: T2, third: T3, fourth: T4):
        self.first = first
        self.second = second
        self.third = third
        self.fourth = fourth

# Example usage:
my_quad = Quad(1, "hello", 3.14, [True])
print(my_quad.first)  # prints 1
print(my_quad.second)  # prints "hello"
print(my_quad.third)   # prints 3.14
print(my_quad.fourth)  # prints [True]
