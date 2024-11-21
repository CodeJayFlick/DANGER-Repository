Here is the equivalent Python code:

```Python
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/inventories', methods=['GET'])
def get_product_inventories():
    return {'product_inventory': 5}

if __name__ == '__main__':
    app.run(debug=True)
```

Note that this Python code uses the Flask web framework to create a simple API. The `@app.route` decorator is used to map URLs to functions, and the `jsonify` function from Flask is used to return JSON data in response to HTTP requests.

The equivalent of Java's `@RestController` annotation is not needed in Python because it does not have an equivalent concept for annotations like Spring Boot has.