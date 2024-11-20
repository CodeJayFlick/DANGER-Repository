import json
from uuid import UUID
from flask import Flask, request, jsonify

app = Flask(__name__)

def define_resources():
    @app.before_request
    def set_content_type():
        return ('Content-Type', 'application/json')

    @app.route('/pets', methods=['POST'])
    def create_pet():
        try:
            new_pet = json.loads(request.data)
            if not (new_pet.get('name') and new_pet.get('breed')):
                return jsonify({'error': 'Invalid name or breed'}), 400
            db_pet = Pet(new_pet['id'], new_pet['name'], new_pet['breed'])
            return jsonify(db_pet.to_dict()), 200

    @app.route('/pets', methods=['GET'])
    def get_pets():
        limit = int(request.args.get('limit', default=10, type=int))
        output_pets = []
        for i in range(limit):
            new_pet = Pet(UUID().hex, PetData.random_name(), PetData.random_breed())
            output_pets.append(new_pet.to_dict())
        return jsonify(output_pets), 200

    @app.route('/pets/<pet_id>', methods=['GET'])
    def get_pet(pet_id):
        new_pet = Pet(UUID().hex, PetData.random_name(), PetData.random_breed())
        return jsonify(new_pet.to_dict()), 200

class Pet:
    def __init__(self, id, name, breed):
        self.id = id
        self.name = name
        self.breed = breed

    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'breed': self.breed}

if __name__ == '__main__':
    define_resources()
    app.run(debug=True)
