class GoldCoin:
    """GoldCoin implementation."""
    
    description = "This is a gold coin."

    def get_description(self):
        return self.description


# Example usage:
coin = GoldCoin()
print(coin.get_description())  # Output: This is a gold coin.
