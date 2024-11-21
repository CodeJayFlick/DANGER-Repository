from flask import Flask, jsonify, request
import requests

app = Flask(__name__)

class Product:
    def __init__(self):
        self.title = None
        self.product_inventories = -1

@app.route('/product', methods=['GET'])
def get_product():
    product = Product()
    
    try:
        product_title_response = requests.get('https://example.com/product-title')
        if product_title_response.status_code == 200:
            product.title = product_title_response.json()['title']
        else:
            product.title = "Error: Fetching Product Title Failed"
            
        inventory_response = requests.get('https://example.com/inventory')
        if inventory_response.status_code == 200:
            product.product_inventories = inventory_response.json()
        else:
            product.product_inventories = -1
    except Exception as e:
        print(f"Error: {str(e)}")
        
    return jsonify(product.__dict__)

if __name__ == '__main__':
    app.run(debug=True)
