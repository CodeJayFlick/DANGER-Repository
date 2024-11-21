import os
from PIL import Image
import numpy as np
import torch
from torchvision import datasets, transforms

class TestImageFolder:
    def test_image_folder(self):
        repository = "test"
        dataset_path = "src/test/resources/imagefolder"

        try:
            model = Model()
            model.set_block(Blocks.identity_block())

            image_folder_dataset = ImageFolder.builder() \
                .set_repository(repository) \
                .opt_pipeline(Pipeline().add(transforms.Resize((100, 100))).add(transforms.ToTensor())) \
                .set_sampling(1, False) \
                .build()

            synsets = ["cat", "dog", "misc"]
            self.assertEqual(synsets, image_folder_dataset.get_synset())

            trainer = model.new_trainer(DefaultTrainingConfig(Loss.softmax_cross_entropy_loss()))

            nd_manager = trainer.get_manager()
            cat_image = Image.open(os.path.join(dataset_path, "cat/kitten.jpg"))
            dog_image = Image.open(os.path.join(dataset_path, "dog/dog_bike_car.jpg"))
            pikachu_image = Image.open(os.path.join(dataset_path, "misc/pikachu.png"))

            cat_tensor = transforms.ToTensor()(transforms.Resize((100, 100))(cat_image))
            dog_tensor = transforms.ToTensor()(transforms.Resize((100, 100))(dog_image))
            pikachu_tensor = transforms.ToTensor()(transforms.Resize((100, 100))(pikachu_image))

            dataset_iterator = trainer.iterate_dataset(image_folder_dataset)
            cat_batch = next(dataset_iterator)
            self.assertTrue(np.allclose(cat_batch.data[0].numpy(), cat_tensor.numpy()))
            self.assertEqual(torch.tensor([0]), cat_batch.labels)

            dog_batch = next(dataset_iterator)
            self.assertTrue(np.allclose(dog_batch.data[0].numpy(), dog_tensor.numpy()))
            self.assertEqual(torch.tensor([1]), dog_batch.labels)

            pikachu_batch = next(dataset_iterator)
            self.assertTrue(np.allclose(pikachu_batch.data[0].numpy(), pikachu_tensor.numpy()))
            self.assertEqual(torch.tensor([2]), pikachu_batch.labels)

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_random_split(self):
        repository = "test"
        dataset_path = "src/test/resources/imagefolder"

        try:
            image_folder_dataset = ImageFolder.builder() \
                .set_repository(repository) \
                .set_sampling(1, False) \
                .build()

            sets = image_folder_dataset.random_split(75, 25)
            self.assertEqual(len(sets), 2)

        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    test_image_folder = TestImageFolder()
    test_image_folder.test_image_folder()
    test_image_folder.test_random_split()

