Here is the equivalent Python code:

```Python
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
```

Please note that Python does not have a direct equivalent to Java's Spring Boot. However, you can use the Flask framework in Python for building web applications.

Also, there is no direct translation of `SpringApplication` and its methods like `run()` because they are specific to the Spring ecosystem which doesn't exist in Python.