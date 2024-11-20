import os
from djl.basicdataset import CocoDetection
from djl.translate import TranslateException
from djl.training import Trainer, TrainingConfig
from djl.nn import Blocks
from djl.loss import Loss

class CocoTest:
    def test_coco_remote(self):
        coco = CocoDetection.builder() \
            .set_usage('TEST') \
            .set_sampling(1, True) \
            .set_limit(3) \
            .build()

        try:
            model = Model.newInstance("model")
            config = TrainingConfig(Loss.L2Loss())
            model.set_block(Blocks.identityBlock())
            trainer = Trainer(model, config)
            for batch in trainer.iterate_dataset(coco):
                self.assertEqual(len(batch.data), 1)
                self.assertEqual(len(batch.labels), 1)
        except Exception as e:
            raise TranslateException(str(e))
