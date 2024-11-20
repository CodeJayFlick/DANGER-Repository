Here is the translation of the given Java code into Python:

```Python
import logging

# Define a logger
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

class LetterComposite:
    def __init__(self):
        pass

    def print(self):
        pass


class Word(LetterComposite):
    def __init__(self, text: str):
        self.text = text

    def print(self):
        LOGGER.info(f"Word: {self.text}")


class Sentence(Word):
    def __init__(self, words: list[str]):
        super().__init__(" ".join(words))
        self.words = words

    def print(self):
        for word in self.words:
            LOGGER.info(word)
        LOGGER.info("")


class Messenger:
    def message_from_orcs(self) -> Sentence:
        return Sentence(["Orcs are coming!", "They will destroy everything."])

    def message_from_elves(self) -> Sentence:
        return Sentence(["Elves are wise", "And they know what to do"])


def main():
    messenger = Messenger()

    LOGGER.info("Message from the orcs:")
    messenger.message_from_orcs().print()

    LOGGER.info("Message from the elves:")
    messenger.message_from_elves().print()


if __name__ == "__main__":
    main()
```

This Python code implements a Composite pattern, where `LetterComposite` is an abstract class that has two concrete subclasses: `Word` and `Sentence`. The `Messenger` class composes these objects into sentences.