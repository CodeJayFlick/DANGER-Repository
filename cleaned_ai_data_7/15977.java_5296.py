import numpy as np
from typing import List, Tuple

class IrisClassificationTranslator:
    def __init__(self):
        self.synset = ["setosa", "versicolor", "virginica"]

    def process_input(self, input: dict) -> list:
        data = [input["sepal_length"], 
                input["sepal_width"],
                input["petal_length"],
                input["petal_width"]]
        array = np.array(data).reshape(1, 4)
        return [array]

    def process_output(self, output: list) -> dict:
        probabilities = [(float(x)) for x in output[0].flatten().tolist()]
        return {"species": self.synset, "probabilities": probabilities}

class IrisClassificationTranslatorFactory:
    def get_supported_types(self) -> List[Tuple[type, type]]:
        return [[IrisFlower, Classifications]]

    def instance(self, input: type, output: type, model: str = None, arguments: dict = None) -> 'IrisClassificationTranslator':
        if not self.is_supported(input, output):
            raise ValueError("Unsupported input/output types.")
        return IrisClassificationTranslator()

class NoBatchifyTranslator:
    pass

# Usage
translator_factory = IrisClassificationTranslatorFactory()
translator = translator_factory.instance(IrisFlower, Classifications)
input_data = {"sepal_length": 5.1, "sepal_width": 3.5, 
              "petal_length": 1.4, "petal_width": 0.2}
output = translator.process_input(input_data)[0]
translator.process_output(output)

