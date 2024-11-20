Here is the translation of the Java code to Python:

```Python
import logging

class HealingPotion:
    def drink(self):
        logging.info("You feel healed. (Potion={})".format(id(self)))

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
```

Note that I've removed the `@Slf4j` annotation and replaced it with a basic configuration of Python's built-in `logging` module, since there is no equivalent to SLF4J in Python.