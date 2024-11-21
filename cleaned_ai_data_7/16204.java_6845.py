import boto3
import json
from typing import List

class SageMakerTest:
    def test_deploy_model(self):
        if not self.has_credential():
            raise Exception("The test requires AWS credentials.")

        criteria = Criteria()
        criteria.set_types(NDList, NDList)
        criteria.opt_model_urls("https://resources.djl.ai/test-models/mlp.tar.gz")
        model = criteria.load_model()

        sage_maker = SageMaker()
        sage_maker.set_model(model)
        sage_maker.opt_bucket_name("djl-sm-test")
        sage_maker.opt_model_name("resnet")
        sage_maker.opt_container_image(
            "125045733377.dkr.ecr.us-east-1.amazonaws.com/djl"
        )
        sage_maker.opt_execution_role(
            "arn:aws:iam::125045733377:role/service-role/DJLSageMaker-ExecutionRole-20210213T1027050"
        )

        sage_maker.deploy()

        image_path = Path("../../examples/src/test/resources/0.png")
        with open(image_path, 'rb') as f:
            image = f.read()
        
        ret = sage_maker.invoke(image)
        list_ = json.loads(ret)
        className = list_[0]['className']
        assert className == "0"

        sage_maker.delete_endpoint()
        sage_maker.delete_endpoint_config()
        sage_maker.delete_sage_maker_model()

    def has_credential(self):
        try:
            cp = DefaultCredentialsProvider.create()
            cp.resolve_credentials()
            return True
        except Exception as e:
            return False

class Criteria:
    pass

class SageMaker:
    pass

class NDList:
    pass
