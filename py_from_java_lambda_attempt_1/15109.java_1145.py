Here is the translation of the given Java code into Python:

```Python
class TrampolineApp:
    def __init__(self):
        self.logger = None

    def main(self, args=None):
        self.logger.info("start pattern")
        result = loop(10, 1)
        self.logger.info("result: {}".format(result))

    def loop(self, times, prod=1):
        if times == 0:
            return prod
        else:
            return lambda: self.loop(times - 1, prod * times)

if __name__ == "__main__":
    app = TrampolineApp()
    app.main(None)
```

Please note that Python does not have a direct equivalent to Java's `Trampoline` class. The code above uses a recursive function (`loop`) and an anonymous lambda function to achieve the same effect as the original Java code.

Also, I did not include any logging mechanism in this translation because it seems like you are using SLF4J for logging in your Java code. Python has its own built-in `logging` module which can be used similarly.