import os
from ai_djl.translate import TranslatorContext
from ai_djl.tensorrt.engine import TrtSession
from ai_djl.ndarray import NDList
from ai_djl.repository.zoo import Criteria, ZooModel
from ai_djl.modality.cv import ImageClassificationTranslator, ToTensor

class MyTranslator:
    def __init__(self):
        self.session = None

    def prepare(self, ctx: TranslatorContext) -> None:
        self.session = TrtSession(ctx.get_block())

    def process_output(self, ctx: TranslatorContext, list: NDList) -> float[] | None:
        return list.head().to_float_array()

    def process_input(self, ctx: TranslatorContext, input: float[]) -> NDList:
        inputs = self.session.get_input_bindings()
        inputs[0].set(FloatBuffer.wrap(input))
        return inputs

class TrtTest:

    def test_trt_onnx(self):
        try:
            engine = Engine("TensorRT")
        except Exception as e:
            raise SkipException(f"Your os configuration doesn't support TensorRT. {e}")

        if not engine.default_device().is_gpu():
            raise SkipException("TensorRT only supports GPU.")

        criteria = Criteria.builder() \
                         .set_types(float, float) \
                         .opt_model_path("src/test/resources/identity.onnx") \
                         .opt_translator(MyTranslator()) \
                         .opt_engine("TensorRT") \
                         .build()

        with ZooModel.load(criteria) as model:
            predictor = model.new_predictor()
            data = [1.0, 2.0, 3.0, 4.0]
            ret = predictor.predict(data)
            assert ret == data

    def test_trt_uff(self):
        try:
            engine = Engine("TensorRT")
        except Exception as e:
            raise SkipException(f"Your os configuration doesn't support TensorRT. {e}")

        if not engine.default_device().is_gpu():
            raise SkipException("TensorRT only supports GPU.")

        synset = list(range(10))
        translator = ImageClassificationTranslator.builder() \
                                    .opt_flag(Image.Flag.GRAYSCALE) \
                                    .opt_synset(synset) \
                                    .opt_apply_softmax(True) \
                                    .add_transform(ToTensor()) \
                                    .opt_batchifier(None) \
                                    .build()

        criteria = Criteria.builder() \
                         .set_types(Image, Classifications) \
                         .opt_model_urls("https://resources.djl.ai/test-models/tensorrt/lenet5.zip") \
                         .opt_translator(translator) \
                         .opt_engine("TensorRT") \
                         .build()

        with ZooModel.load(criteria) as model:
            predictor = model.new_predictor()
            path = os.path.join("../../examples/src/test/resources", "0.png")
            image = ImageFactory.get_instance().from_file(path)
            ret = predictor.predict(image)
            assert ret.best().get_class_name() == "0"

    def test_serialized_engine(self):
        try:
            engine = Engine("TensorRT")
        except Exception as e:
            raise SkipException(f"Your os configuration doesn't support TensorRT. {e}")

        if not engine.default_device().is_gpu():
            raise SkipException("TensorRT only supports GPU.")

        device = engine.default_device()
        sm = CudaUtils.get_compute_capability(device.device_id)
        criteria = Criteria.builder() \
                         .set_types(float, float) \
                         .opt_model_path(os.path.join("src", "test", "resources", f"identity_{sm}.trt")) \
                         .opt_translator(MyTranslator()) \
                         .opt_engine("TensorRT") \
                         .build()

        with ZooModel.load(criteria) as model:
            predictor = model.new_predictor()
            data = [1.0, 2.0, 3.0, 4.0]
            ret = predictor.predict(data)
            assert ret == data
