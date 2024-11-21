Here's the equivalent Python code:

```Python
class GoldCoin:
    """GoldCoin implementation."""
    
    description = "This is a gold coin."

    def get_description(self):
        return self.description


# Example usage:
coin = GoldCoin()
print(coin.get_description())  # Output: This is a gold coin.
```

Note that Python does not have direct equivalents for Java's `package`, `public class`, and `@Override` annotations. The equivalent of these in Python are:

- No package declaration (Python doesn't support packages like Java, but you can use modules)
- A simple class definition with the same name as the file
- No need to override methods explicitly; just define them