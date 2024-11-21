# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import flask

app = flask.Flask(__name__)

@app.route('/information', methods=['GET'])
def get_product_title():
    return 'The Product Title.'

if __name__ == '__main__':
    app.run(debug=True)
