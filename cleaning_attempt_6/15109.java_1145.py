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
