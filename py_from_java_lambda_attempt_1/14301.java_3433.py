Here is the translation of the Java code to Python:

```Python
import logging

class ArcherView:
    def display(self):
        logging.info("Displaying archers")

if __name__ == "__main__":
    ArcherView().display()
```

Note that I did not include any equivalent for Lombok's `@Slf4j` annotation, as it is a Java-specific feature. In Python, you would typically use the built-in `logging` module to log messages.

Also, note that in Python, we don't have an exact equivalent of Java's interface concept (the `View` class). Instead, we can define a base class with abstract methods and then create concrete classes that inherit from it. However, since this is not necessary for the provided code snippet, I simply omitted any such definition.

Finally, note that in Python, you would typically use an if statement to check whether your script is being run as the main program (i.e., `if __name__ == "__main__":`) and then call the relevant methods. This is because Python can be imported as a module by other scripts, so we need to ensure that our code only runs when it's actually executed directly.