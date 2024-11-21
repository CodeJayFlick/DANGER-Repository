Here is the translation of the Java code to Python:

```Python
import logging

class EventObserver:
    def on_event(self, event):
        logging.info("Received event from the King's Hand: {}".format(event))

if __name__ == "__main__":
    class KingJoffrey(EventObserver):
        pass

    king_joffrey = KingJoffrey()
    # You would use this object to observe events
```

Note that Python does not have a direct equivalent of Java's `@Slf4j` annotation, which is used for logging. Instead, we import the built-in `logging` module and create an instance of it in our class.

Also note that there are no packages or imports needed in this translation because Python uses different concepts than Java (e.g., modules instead of packages).