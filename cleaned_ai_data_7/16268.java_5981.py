import os
from typing import List, Dict
import json
import numpy as np
from PIL import Image

class CustomTranslatorTest:
    def __init__(self):
        self.model_dir = 'build/models/mlp'
        self.data = None

    @classmethod
    def setup(cls) -> None:
        if Engine().get_engine_name() != "MXNet":
            return
        
        os.makedirs(self.model_dir, exist_ok=True)
        
        criteria = Criteria(Image(), Classifications())
        criteria.set_types(Image(), Classifications())
        criteria.opt_artifact_id("ai.djl.mxnet:mlp")
        model = criteria.load_model()
        
        symbol_file_path = os.path.join(self.model_dir, "mlp-symbol.json")
        with open(symbol_file_path, 'wb') as f:
            f.write(model.get_artifact_as_bytes("mlp-symbol.json"))
        
        synset_file_path = os.path.join(self.model_dir, "synset.txt")
        with open(synset_file_path, 'w') as f:
            f.write(model.get_artifact_as_string("synset.txt").decode('utf-8'))
        
        param_file_path = os.path.join(self.model_dir, "mlp-0000.params")
        with open(param_file_path, 'wb') as f:
            f.write(model.get_artifact_as_bytes("mlp-0000.params"))
    
    @classmethod
    def tearDown(cls) -> None:
        if Engine().get_engine_name() != "MXNet":
            return
        
        os.rmdir(self.model_dir)

    def test_image_classification_translator(self):
        if Engine().get_engine_name() != "MXNet":
            return
        
        # load RawTranslator
        self.run_raw_translator()
        
        # load default translator with criteria
        arguments = {"width": 28, "height": 28, "flag": Image.Flag.GRAYSCALE.name(), "applySoftmax": True}
        self.run_image_classification(Application.CV.IMAGE_CLASSIFICATION, arguments, "ImageServingTranslator")
        
        lib_dir_path = os.path.join(self.model_dir, "lib")
        classes_dir_path = os.path.join(lib_dir_path, "classes")
        os.makedirs(classes_dir_path, exist_ok=True)
        
        prop = Properties()
        prop.put("application", Application.CV.IMAGE_CLASSIFICATION.getPath())
        prop.put("width", 28)
        prop.put("height", 28)
        prop.put("flag", Image.Flag.GRAYSCALE.name())
        prop.put("applySoftmax", True)
        conf_file_path = os.path.join(self.model_dir, "serving.properties")
        with open(conf_file_path, 'w') as f:
            prop.store(f, "")
        
        self.run_image_classification(Application.UNDEFINED, None, "ImageServingTranslator")
        
        libs_dir_path = os.path.join(self.model_dir, "libs")
        os.rename(lib_dir_path, libs_dir_path)
        classes_dir_path = os.path.join(libs_dir_path, "classes")
        src_file_path = 'src/test/translator/MyTranslator.java'
        dest_file_path = os.path.join(classes_dir_path, 'MyTranslator.java')
        with open(dest_file_path, 'w') as f:
            f.write(open(src_file_path).read())
        
        # load translator from classes folder
        self.run_image_classification(Application.UNDEFINED, None, "MyTranslator")
        
        jar_file_path = os.path.join(libs_dir_path, "example.jar")
        ZipUtils.zip(classes_dir_path, jar_file_path, False)
        os.remove(dest_file_path)

    def test_ssd_translator(self):
        if Engine().get_engine_name() != "MXNet":
            return
        
        criteria = Criteria(Image(), DetectedObjects())
        criteria.set_types(Image(), DetectedObjects())
        criteria.opt_artifact_id("ai.djl.mxnet:ssd")
        
        model_url = None
        with criteria.load_model() as model:
            model_url = model.get_model_path().to_uri().to_url().toString()
        
        criteria = Criteria(Input(), Output())
        criteria.set_types(Input(), Output())
        criteria.opt_model_urls([model_url])
        criteria.opt_argument("width", 512)
        criteria.opt_argument("height", 512)
        criteria.opt_argument("resize", True)
        criteria.opt_argument("rescale", True)
        criteria.opt_argument("synsetFileName", "classes.txt")
        criteria.opt_argument(
            "translatorFactory",
            "ai.djl.modality.cv.translator.SingleShotDetectionTranslatorFactory"
        )
        criteria.opt_model_name("ssd_512_resnet50_v1_voc")
        
        image_file_path = 'examples/src/test/resources/dog_bike_car.jpg'
        with open(image_file_path, 'rb') as f:
            buf = f.read()
        
        with criteria.load_model() as model, model.new_predictor() as predictor:
            input_ = Input()
            input_.add(buf)
            output = predictor.predict(input_)
            
            assert output.get_code() == 200
            content = output.get_as_string(0).decode('utf-8')
            type_token = TypeToken[List[Classification]]()
            result = json.loads(content, object_hook=lambda d: Classification(**d))
            assert result[0].get_class_name() == "car"

    def run_image_classification(self, application: Application, arguments: Dict[str, str], translator_name: str):
        criteria = Criteria(Input(), Output())
        criteria.set_types(Input(), Output())
        criteria.opt_application(application)
        criteria.opt_arguments(arguments)
        criteria.opt_model_path(self.model_dir)
        
        with criteria.load_model() as model, model.new_predictor() as predictor:
            translator = model.get_translator()
            assert translator.__class__.__name__ == translator_name
            
            input_ = Input()
            input_.add(np.array([self.data]))
            output = predictor.predict(input_)
            
            assert output.get_code() == 200
            content = output.get_as_string(0).decode('utf-8')
            type_token = TypeToken[List[Classification]]()
            result = json.loads(content, object_hook=lambda d: Classification(**d))
            assert result[0].get_class_name() == "0"

    def run_raw_translator(self):
        criteria = Criteria(Input(), Output())
        criteria.set_types(Input(), Output())
        criteria.opt_model_path(self.model_dir)
        
        with criteria.load_model() as model, model.new_predictor() as predictor:
            manager = model.get_nd_manager()
            
            # manually pre process
            is_ = BytesIO(self.data)
            image = Image.open(is_)
            array = np.array(image).astype(np.float32) / 255.0
            array = np.expand_dims(array, axis=0)
            list_ = [array]
            
            input_ = Input()
            input_.add(list_)
            output = predictor.predict(input_)
            
            assert output.get_code() == 200
            
            # manually post process
            list_ = output.get_data_as_nd_list(manager)[0][0].softmax(0).tolist()[0]
            classes = model.get_artifact("synset.txt", lambda f: [line.strip() for line in f.readlines()])
            result = Classifications(classes, np.array(list_))
            assert result.best().get_class_name() == "0"

if __name__ == "__main__":
    test_ssd_translator()
