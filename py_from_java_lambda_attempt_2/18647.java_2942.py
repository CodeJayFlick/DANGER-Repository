Here is the equivalent Python code:

```python
from flask import Flask, jsonify

app = Flask(__name__)

HELLO_MESSAGE = "Hello"

@app.route('/hello', methods=['GET'])
def hello():
    return jsonify({'message': HELLO_MESSAGE})

if __name__ == '__main__':
    app.run(debug=True)
```

Note that this code uses the Flask web framework, which is a popular choice for building Python web applications. The `@app.route` decorator defines an endpoint at `/hello` that responds to GET requests and returns a JSON response with the message `"Hello"`.