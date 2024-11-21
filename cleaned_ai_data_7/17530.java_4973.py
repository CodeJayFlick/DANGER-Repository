import math

class UDTFExp:
    def set_transformer(self):
        self.transformer = lambda x: math.exp(x)

# Example usage
udtf_exp = UDTFExp()
print(udtf_exp.set_transformer())  # prints a function that applies exp() to its input
