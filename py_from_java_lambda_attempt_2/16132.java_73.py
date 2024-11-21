Here is the translation of the given Java code into Python:

```Python
import torch
from torchvision import transforms
from PIL import Image
import numpy as np

class FeatureExtraction:
    def __init__(self):
        pass

    @staticmethod
    def main():
        if not torch.cuda.is_available():
            print("This example only works for PyTorch.")
            return
        
        image_file = "src/test/resources/kana1.jpg"
        img = Image.open(image_file)

        feature = FeatureExtraction.predict(img)
        if feature is not None:
            print(feature.tolist())

    @staticmethod
    def predict(img):
        transform = transforms.Compose([
            transforms.ToTensor(),
            transforms.Normalize((0.5, 0.5, 0.5), (0.5, 0.5, 0.5))
        ])

        img_tensor = transform(img)
        
        # Load the model
        device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
        model = torch.jit.load("face_feature.pth", map_location=device)

        with torch.no_grad():
            output = model(torch.unsqueeze(img_tensor, 0)).numpy().flatten()

        return output.tolist()


if __name__ == "__main__":
    FeatureExtraction.main()
```

Please note that the original Java code is using a specific PyTorch model and it's not possible to directly translate this into Python. The provided translation assumes you have your own custom PyTorch model, `face_feature.pth`, which can be loaded in the same way as shown above.

Also, please ensure that the necessary libraries are installed (`torchvision` for image processing) before running this code.