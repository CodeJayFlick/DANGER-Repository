import os
from ai_djl.translate import TranslateException
from ai_djl.repository.zoo import ZooModel, Criteria
from ai_djl.modality.cv import ImageFactory
from ai_djl.inference.predictor import Predictor
from ai_djl.modality.classifications import Classifications

class TfLiteTest:
    def test_tflite(self):
        if os.name.lower().startswith("win"):
            raise SkipException("test only work on mac and Linux")

        criteria = Criteria()
        criteria.set_types(ImageFactory, Classifications)
        criteria.opt_engine("TFLite")
        criteria.opt_filter("dataset", "aiyDish")
        model = ZooModel.load_model(criteria)

        try:
            predictor = model.new_predictor()
            image = ImageFactory.from_url("https://resources.djl.ai/images/sachertorte.jpg")
            prediction = predictor.predict(image)
            assert prediction.best().get_class_name() == "Sachertorte"
        except (TranslateException, Exception) as e:
            raise
