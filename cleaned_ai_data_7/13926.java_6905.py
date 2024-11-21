class LetterComposite:
    def __init__(self):
        self.children = []

    def add(self, letter):
        self.children.append(letter)

    def count(self):
        return len(self.children)

    def print_this_before(self):
        pass

    def print_this_after(self):
        pass

    def print(self):
        self.print_this_before()
        for child in self.children:
            child.print()
        self.print_this_after()

class Letter(LetterComposite):  # Assuming there's a class called 'Letter'
    pass
