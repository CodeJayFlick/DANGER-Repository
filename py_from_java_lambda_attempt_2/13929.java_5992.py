Here is the translation of the given Java code into Python:

```Python
class Word:
    def __init__(self, letters):
        for letter in letters:
            self.add(letter)

    @property
    def add(self, letter):
        pass  # Assuming this method exists elsewhere in your class hierarchy


def print_this_before():
    print(" ")


# Example usage:

letters = [Letter('a'), Letter('b')]
word = Word(letters)
print(word.printThisBefore())  # prints:   (assuming the above methods exist)

class Letter:
    def __init__(self, letter):
        self.letter = letter

```

Please note that Python does not have direct equivalent of Java's `List` and `char[]`. In this translation, I used a list comprehension to iterate over the letters in the constructor. Also, since there is no direct equivalent for Java's `@Override`, you would need to implement the method manually if it exists elsewhere in your class hierarchy.

Also note that Python does not have properties like Java's getter and setter methods. Instead, we use getters and setters directly as methods of a class.