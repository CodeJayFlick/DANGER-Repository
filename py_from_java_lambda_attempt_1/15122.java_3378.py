Here is the translation of the Java code to Python:
```
import logging

class BallItem:
    def __init__(self):
        self.is_suspended = False
        self.twin = None

    @property
    def twin(self):
        return self._twin

    @twin.setter
    def twin(self, value):
        self._twin = value

    def do_draw(self):
        logging.info("doDraw")

    def move(self):
        logging.info("move")

    def click(self):
        if not self.is_suspended:
            self.is_suspended = True
            self.twin.suspend_me()
        else:
            self.is_suspended = False
            self.twin.resume_me()

class BallThread:
    pass  # This class is not implemented in the original Java code, so I left it as a placeholder

# Example usage:
if __name__ == "__main__":
    ball_item = BallItem()
    logging.basicConfig(level=logging.INFO)
    ball_thread = BallThread()  # Replace with actual implementation
    ball_item.twin = ball_thread
    ball_item.click()  # Try clicking the ball item to see it suspend and resume
```
Note that I had to make some assumptions about the `BallThread` class, as its implementation was not provided in the original Java code. In Python, we don't have a direct equivalent of Java's `@Slf4j` annotation for logging, so I used the built-in `logging` module instead.