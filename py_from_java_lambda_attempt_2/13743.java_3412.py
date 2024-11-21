Here is the translation of the Java code to Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import flask

app = flask.Flask(__name__)

@app.route('/information', methods=['GET'])
def get_product_title():
    return 'The Product Title.'

if __name__ == '__main__':
    app.run(debug=True)
```

Note that Python does not have a direct equivalent to Java's `@RestController` and `@GetMapping`. Instead, we use the Flask web framework to create routes for our API. The `/information` route is mapped to the `get_product_title()` function, which returns 'The Product Title.' when called with a GET request.