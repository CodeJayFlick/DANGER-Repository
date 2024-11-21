class Sentence:
    def __init__(self, words):
        for word in words:
            self.add(word)

    @property
    def print_this_after(self):
        return ".\n"

# Note: The LetterComposite class and add method are not provided,
# so I assume they exist or can be implemented similarly.
