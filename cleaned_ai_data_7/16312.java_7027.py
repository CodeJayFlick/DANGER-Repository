import logging
from unittest import TestCase
import os
import sys

class IntegrationTests(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)

    @classmethod
    def run_integration_tests(cls, args=None):
        default_engine = os.environ.get('AI_DJL_DEFAULT_ENGINE')
        
        if not default_engine:
            engines = ['MXNet']
            # TODO: windows CPU build is having OOM issue if 3 engines are loaded and running tests together
            if sys.platform.startswith('win'):
                engines = ['MXNet']
            else:
                engines = ['MXNet', 'PyTorch', 'TensorFlow', 'XGBoost']

        for engine in engines:
            os.environ['AI_DJL_DEFAULT_ENGINE'] = engine
            self.logger.info("Testing engine: %s...", engine)
            self.assertTrue(IntegrationTest().run_tests(args))
            
            # currently each engine will reserve a certain amount of memory and hold it until process terminate so running 3 different engines sequentially without calling System.exit() causes OOM issue. For GPU env, only defaultEngine is run
            if CudaUtils.has_cuda():
                break

class IntegrationTest:
    def __init__(self):
        pass
    
    def run_tests(self, args=None):
        # TO DO: implement the logic to run tests for each engine
        return True
