Here is the translation of the Java code to Python:
```
import logging

class ProjectileStrategy:
    def execute(self):
        logging.info("You shoot the dragon with the magical crossbow and it falls dead on the ground!")

if __name__ == "__main__":
    import logging.config
    logging.config.dictConfig({
        "version": 1,
        "formatters": {
            "default": {"format": "%(asctime)s - %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s"}
        },
        "handlers": {
            "console": {"class": "logging.StreamHandler", "level": logging.INFO}
        },
        "root": {"level": logging.INFO, "handlers": ["console"]}
    })
```
Note that I've removed the `@Slf4j` annotation and replaced it with a simple import of the `logging` module. In Python, we don't need an explicit logger instance like in Java; instead, we can configure the logging system using a dictionary.

Also, since there is no equivalent to Java's `DragonSlayingStrategy` interface or abstract class in Python, I've simply defined a regular class with an `execute()` method.