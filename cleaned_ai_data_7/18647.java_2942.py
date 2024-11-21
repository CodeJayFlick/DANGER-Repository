from flask import Flask, jsonify

app = Flask(__name__)

HELLO_MESSAGE = "Hello"

@app.route('/hello', methods=['GET'])
def hello():
    return jsonify({'message': HELLO_MESSAGE})

if __name__ == '__main__':
    app.run(debug=True)
