import torch
from ai_djl.translate import TranslateException
from ai_djl.pytorch.engine import PtNDArray, PtSymbolBlock
from ai_djl.pytorch.jni import JniUtils
from ai_djl.repository.zoo import ZooModel

class TorchScriptTest:
    def test_dict_input(self):
        try:
            manager = torch.ondemand()
            criteria = Criteria().set_types(NDList(), NDList()).opt_model_urls("https://resources.djl.ai/test-models/dict_input.zip").opt_progress(new ProgressBar())
            model = criteria.load_model()
            predictor = model.new_predictor()
            array = PtNDArray(manager.ones((2, 2)))
            array.name = "input1.input"
            output = predictor.predict([array])
            assert output.singleton_or_throw() == array
            model_file = model.model_path().resolve(model.name + ".pt")
        except ModelException as e:
            raise TranslateException(e)

    def test_input_output(self):
        try:
            criteria = Criteria().set_types(NDList(), NDList()).opt_model_urls("djl://ai.djl.pytorch/resnet/0.0.1/traced_resnet18").opt_progress(new ProgressBar())
            model = criteria.load_model()
            manager = PtNDManager(model.nd_manager)
            model_file = model.model_path().resolve("traced_resnet18.pt")
            with open(model_file, 'rb') as f:
                block = JniUtils.load_module(manager, f.read(), True, False)
                os = bytearray()
                JniUtils.write_module(block, os, True)
                bis = bytes(os).decode('utf-8')
        except IOException as e:
            raise TranslateException(e)

if __name__ == "__main__":
    test_dict_input = TorchScriptTest().test_dict_input
    test_input_output = TorchScriptTest().test_input_output

