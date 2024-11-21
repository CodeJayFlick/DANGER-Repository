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
