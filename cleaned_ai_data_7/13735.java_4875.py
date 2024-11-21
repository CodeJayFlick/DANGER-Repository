# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import os

class App:
    def __init__(self):
        pass

if __name__ == "__main__":
    import sys
    from flask import Flask, request, jsonify
    
    app = Flask(__name__)
    
    @app.route('/api', methods=['GET'])
    def get_api():
        return {'message': 'Hello World'}, 200
    
    if len(sys.argv) > 1:
        port = int(os.environ.get('PORT', sys.argv[1]))
    else:
        port = 5000

    app.run(port=port)
