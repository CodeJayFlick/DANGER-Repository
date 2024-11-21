class Messenger:
    def message_from_orcs(self):
        words = [
            Word('W', 'h', 'e', 'r', 'e'),
            Word('t', 'h', 'e', 'r', 'e'),
            Word('i', 's'),
            Word('a'),
            Word('w', 'h', 'i', 'p'),
            Word('t', 'h', 'e', 'r', 'e'),
            Word('i', 's'),
            Word('a'),
            Word('w', 'a', 'y')
        ]
        return Sentence(words)

    def message_from_elves(self):
        words = [
            Word('M', 'u', 'c', 'h'),
            Word('w', 'i', 'n', 'd'),
            Word('p', 'o', 'u', 'r', 's'),
            Word('f', 'r', 'o', 'm'),
            Word('y', 'o', 'u', 'r'),
            Word('m', 'o', 'u', 't', 'h')
        ]
        return Sentence(words)


class LetterComposite:
    pass


class Word:
    def __init__(self, *letters):
        self.letters = list(letters)

    def __str__(self):
        return ''.join(self.letters)


class Sentence(LetterComposite):
    def __init__(self, words):
        self.words = list(words)
