import argparse
from djl import Model, Mnist, Mlp, Engine, Metrics, Block, Shape
from djl.training import Trainer, TrainingResult, DefaultTrainingConfig, EasyTrain
from djl.translate.TranslateException import TranslateException

class TrainMnist:
    def __init__(self):
        pass

    @staticmethod
    def run_example(args):
        arguments = Arguments().parse_args(args)
        if not arguments:
            return None
        
        # Construct neural network
        block = Mlp(28*28, 10, [128,64])

        try:
            model = Model("mlp")
            model.set_block(block)

            # get training and validation dataset
            train_set = Mnist.get_dataset(Dataset.Usage.TRAIN, arguments)
            val_set = Mnist.get_dataset(Dataset.Usage.TEST, arguments)

            # setup training configuration
            config = TrainMnist.setup_training_config(arguments)

            try:
                trainer = model.new_trainer(config)
                trainer.set_metrics(Metrics())

                input_shape = Shape(1, 28*28)

                # initialize trainer with proper input shape
                trainer.initialize(input_shape)

                EasyTrain.fit(trainer, arguments.get_epoch(), train_set, val_set)

                return trainer.get_training_result()
            except Exception as e:
                raise TranslateException(str(e))
        finally:
            pass

    @staticmethod
    def setup_training_config(arguments):
        output_dir = arguments.output_dir
        listener = SaveModelTrainingListener(output_dir)
        listener.set_save_model_callback(
            lambda trainer: 
            {
                result = trainer.get_training_result()
                model = trainer.get_model()
                accuracy = result.validate_evaluation("Accuracy")
                model.setProperty("Accuracy", f"{accuracy:.5f}")
                model.setProperty("Loss", f"{result.validate_loss():.5f}")
            }
        )
        return DefaultTrainingConfig(Loss.softmax_cross_entropy_loss())
                  .add_evaluator(Accuracy())
                  .opt_devices(Engine.getInstance().get_devices(arguments.max_gpus))
                  .add_training_listeners(TrainingListenerDefaults.logging(output_dir))
                  .add_training_listeners(listener)

    @staticmethod
    def get_dataset(usage, arguments):
        mnist = Mnist.builder()
                         .set_usage(usage)
                         .set_sampling(arguments.batch_size, True)
                         .opt_limit(arguments.limit)
                         .build()
        mnist.prepare(argparse.ArgumentParser())
        return mnist

if __name__ == "__main__":
    try:
        TrainMnist.run_example(sys.argv[1:])
    except Exception as e:
        print(f"Error: {str(e)}")
