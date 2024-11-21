from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/inventories', methods=['GET'])
def get_product_inventories():
    return {'product_inventory': 5}

if __name__ == '__main__':
    app.run(debug=True)
