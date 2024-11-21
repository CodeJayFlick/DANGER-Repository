# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import logging

class App:
    def __init__(self):
        pass

    @staticmethod
    def main(args=None):
        view = View()
        view.create_view()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        App.main(sys.argv[1:])
    else:
        App.main(None)

class View:
    def create_view(self):
        pass

logging.basicConfig(level=logging.INFO)
