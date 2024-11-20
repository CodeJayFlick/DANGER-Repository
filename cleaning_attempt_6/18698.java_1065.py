import uuid
from flask import Flask, request, jsonify

app = Flask(__name__)

class PingController:
    def __init__(self):
        self.model = ""
        self.id = None
        self.list = []

    # GET /ping/1
    def show(self):
        return {"show": "Hello, World!"}

    # GET /
    def index(self):
        self.model = "Hello, World!"
        return {"index": "Hello, World!"}, 200

    # POST /
    def create(self):
        self.model = str(uuid.uuid4())
        return {"success": f"Created with ID {self.model}"}

    # PUT /ping/1
    def update(self):
        # TODO: UPDATE LOGIC
        return "UPDATE SUCCESS"

    # DELETE /ping/1
    def destroy(self):
        # TODO: DELETE LOGIC
        return "DELETE SUCCESS"

    def set_id(self, id):
        if id is not None:
            self.model = "New model instance"
        self.id = id

    def get_model(self):
        if self.list:
            return self.list
        elif not self.model:
            self.model = "Pong"
        return self.model


@app.route('/ping', methods=['GET'])
def ping_index():
    controller = PingController()
    response, code = controller.index()
    return jsonify(response), code

@app.route('/ping/1', methods=['GET'])
def ping_show():
    controller = PingController()
    response = controller.show()
    return jsonify(response)

@app.route('/ping', methods=['POST'])
def ping_create():
    controller = PingController()
    response, _ = controller.create()
    return jsonify(response), 201

@app.route('/ping/1', methods=['PUT'])
def ping_update():
    controller = PingController()
    response = controller.update()
    return jsonify({"message": response})

@app.route('/ping/1', methods=['DELETE'])
def ping_destroy():
    controller = PingController()
    response = controller.destroy()
    return jsonify({"message": response})
