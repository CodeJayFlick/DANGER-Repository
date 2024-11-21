Here is the translation of the given Java code into Python:

```Python
import torch
from torchvision import datasets, transforms
from torch.nn import Linear, BatchNorm2d, Conv2d, MaxPool2d, Sequential, Module
from torch.optim import Adam
from torch.utils.data import DataLoader, random_split

class TrainResnetWithCifar10:
    def __init__(self):
        pass

    @staticmethod
    def run_example(args):
        arguments = Arguments().parse_args(args)
        
        if arguments is None:
            return None
        
        try:
            model = get_model(arguments)
            
            # Get training dataset
            train_dataset, validation_dataset = get_datasets(model, arguments)

            # Setup training configuration
            config = setup_training_config(arguments)

            trainer = EasyTrain(model, config)
            trainer.set_metrics(Metrics())
            input_shape = (1, 3, 32, 32)  # CIFAR10 is 32x32 image and preprocessed into NCHW NDArray
            
            # Initialize trainer with proper input shape
            trainer.initialize(input_shape)
            
            EasyTrain.fit(trainer, arguments.get_epoch(), train_dataset, validation_dataset)

            result = trainer.get_training_result()
            model.set_property("Epoch", str(result.get_epoch()))
            model.set_property("Accuracy", f"{result.get_validate_evaluation('accuracy'):.5f}")
            model.set_property("Loss", f"{result.get_validate_loss():.5f}")

            # Save the trained model
            model.save("build/model", "resnetv1")

            classifications = test_save_parameters(model, Path("build/model"))
            print(f"Predict result: {classifications.topk(3)}")
            
        except (IOException, ModelException, TranslateException) as e:
            logger.error(e)

    @staticmethod
    def get_model(arguments):
        is_symbolic = arguments.get_is_symbolic()
        pre_trained = arguments.get_pre_trained()
        
        if is_symbolic and not pre_trained:
            # Load the model
            return SequentialBlock(ResNetV1().build())
            
        elif pre_trained:
            # Load pre-trained imperative ResNet50 from DJL model zoo
            return BasicModelZoo("resnetv1")
            
        else:
            # Construct new ResNet50 without pre-trained weights
            block = Sequential(
                Conv2d(3, 64, kernel_size=7),
                BatchNorm2d(),
                MaxPool2d(kernel_size=3)
            )
            
            return Model(block)

    @staticmethod
    def test_save_parameters(model_path):
        # Load the model and make predictions on a sample image
        translator = ImageClassificationTranslator()
        
        img = ImageFactory().from_url("src/test/resources/airplane1.png")
        
        criteria = Criteria(Image, Classifications)
        criteria.set_model_path(model_path)
        criteria.set_translator(translator)
        criteria.set_block(model.get_block())
        model = criteria.load_model()
        predictor = model.new_predictor()
        
        return predictor.predict(img)

    @staticmethod
    def setup_training_config(arguments):
        config = DefaultTrainingConfig(Loss.softmax_cross_entropy_loss())
        config.add_evaluator(Accuracy())
        devices = Engine().get_devices(arguments.get_max_gpus())
        config.set_devices(devices)
        config.add_training_listeners(TrainingListenerDefaults.logging(arguments.get_output_dir()))
        
        return config

    @staticmethod
    def get_datasets(model, arguments):
        pipeline = Pipeline(
            ToTensor(),
            Normalize(Cifar10.NORMALIZE_MEAN, Cifar10.NORMALIZE_STD)
        )
        
        cifar10_train, _ = random_split(cifar10(), 0.8)
        train_dataset = DataLoader(cifar10_train, batch_size=arguments.get_batch_size())
        validation_dataset = DataLoader(_, batch_size=arguments.get_batch_size())

        return train_dataset, validation_dataset

class Arguments:
    def __init__(self):
        pass
    
    @staticmethod
    def parse_args(args):
        # Parse the command line arguments here
        pass

    @property
    def is_symbolic(self):
        # Get whether it's symbolic or not from the parsed args
        pass

    @property
    def pre_trained(self):
        # Get whether it's pre-trained or not from the parsed args
        pass

    @property
    def max_gpus(self):
        # Get the maximum number of GPUs to use for training
        pass

    @property
    def output_dir(self):
        # Get the directory where logs should be saved during training
        pass

class Cifar10:
    NORMALIZE_MEAN = 0.5
    NORMALIZE_STD = 0.2
    
    @staticmethod
    def builder():
        return Cifar10()

    @property
    def usage(self):
        # Get the dataset usage (training or testing)
        pass

    @property
    def batch_size(self):
        # Get the batch size for training and validation datasets
        pass

    @property
    def limit(self):
        # Get the maximum number of samples to use in each epoch
        pass

class Arguments:
    def __init__(self):
        pass
    
    @staticmethod
    def parse_args(args):
        # Parse the command line arguments here
        pass

    @property
    def is_symbolic(self):
        # Get whether it's symbolic or not from the parsed args
        pass

    @property
    def pre_trained(self):
        # Get whether it's pre-trained or not from the parsed args
        pass

    @property
    def max_gpus(self):
        # Get the maximum number of GPUs to use for training
        pass

    @property
    def output_dir(self):
        # Get the directory where logs should be saved during training
        pass