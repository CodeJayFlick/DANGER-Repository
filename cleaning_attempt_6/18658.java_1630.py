from flask import Flask, jsonify

app = Flask(__name__)

hello_message = "Hello"

@app.route('/hello', methods=['GET'])
def hello():
    return jsonify({'message': hello_message})

if __name__ == '__main__':
    app.run(debug=True)
