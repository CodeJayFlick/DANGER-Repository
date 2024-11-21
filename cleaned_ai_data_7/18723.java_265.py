from flask import Flask, request, jsonify
import uuid
import random

app = Flask(__name__)

class Pet:
    def __init__(self):
        self.id = str(uuid.uuid4())
        self.name = None
        self.breed = None
        self.date_of_birth = None

pet_data = {
    "names": ["Fido", "Rex", "Bella", "Luna"],
    "breeds": ["Golden Retriever", "Poodle", "German Shepherd", "Labrador"],
    "dates_of_birth": [str(random.randint(1990, 2015)) for _ in range(4)]
}

@app.route('/pets', methods=['POST'])
def create_pet():
    new_pet = Pet()
    if not (new_pet.name and new_pet.breed):
        return jsonify({"error": "Pet name or breed is required"}), 400
    else:
        new_pet.id = str(uuid.uuid4())
        return jsonify(new_pet.__dict__)

@app.route('/pets', methods=['GET'])
def list_pets():
    limit = int(request.args.get('limit', default=10, type=int))
    pets = [Pet() for _ in range(limit)]
    for pet in pets:
        pet.id = str(uuid.uuid4())
        pet.name = random.choice(pet_data["names"])
        pet.breed = random.choice(pet_data["breeds"])
        pet.date_of_birth = random.choice(pet_data["dates_of_birth"])
    return jsonify([pet.__dict__ for pet in pets])

@app.route('/pets/<string:pet_id>', methods=['GET'])
def get_pet(pet_id):
    new_pet = Pet()
    new_pet.id = str(uuid.uuid4())
    new_pet.name = random.choice(pet_data["names"])
    new_pet.breed = random.choice(pet_data["breeds"])
    new_pet.date_of_birth = random.choice(pet_data["dates_of_birth"])
    return jsonify(new_pet.__dict__)

if __name__ == '__main__':
    app.run(debug=True)
