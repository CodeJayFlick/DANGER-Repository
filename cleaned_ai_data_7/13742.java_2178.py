# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import os

class InformationApplication:
    def __init__(self):
        pass

if __name__ == "__main__":
    # Run Flask app if this script is run directly, not imported as module.
    from flask import Flask
    app = Flask(__name__)

    @app.route('/')
    def hello_world():
        return 'Hello, World!'

    if __name__ == '__main__':
        app.run(debug=True)
