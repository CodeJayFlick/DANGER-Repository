Here is the translation of the Java code to Python:

```Python
import logging

class MeleeStrategy:
    def execute(self):
        logging.info("With your Excalibur you sever the dragon's head!")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
```

Note that in this translation, I've used Python's built-in `logging` module to achieve similar functionality as Java's SLF4J. The `@Slf4j` annotation is not directly translatable to Python and has been omitted.