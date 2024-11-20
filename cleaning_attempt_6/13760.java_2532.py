# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import springboot as sb

class App:
    """API Gateway pattern implementation for an e-commerce site."""

    def __init__(self):
        pass

    @sbBootApplication
    def main(self, args):
        sb.run(App, args)

if __name__ == "__main__":
    app = App()
    app.main(sys.argv[1:])
