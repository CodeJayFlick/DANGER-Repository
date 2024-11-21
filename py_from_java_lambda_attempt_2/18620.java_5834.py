Here is the equivalent Python code:

```Python
import unittest
from unittest.mock import patch, Mock
import spark

class InitExceptionHandlerTest(unittest.TestCase):

    TEST_EXCEPTION_MESSAGE = "test exception"
    embedded_server = Mock(spec=spark.LambdaEmbeddedServer)

    def test_init_exception(self):
        with patch.object(embedded_server, 'ignite', side_effect=lambda *args: ContainerInitializationException(TEST_EXCEPTION_MESSAGE)):
            server_factory = spark.LambdaEmbeddedServerFactory(embedded_server)
            handler = spark.SparkLambdaContainerHandler(AwsProxyRequest, AwsProxyResponse,
                                                         AwsProxyHttpServletRequestReader(), 
                                                         AwsProxyHttpServletResponseWriter(),
                                                         AwsProxySecurityContextWriter(), 
                                                         AwsProxyExceptionHandler(), 
                                                         server_factory)

            configure_routes()
            spark.await_initialization()

    def test_stop_spark(self):
        with patch.object(embedded_server, 'stop'):
            reset(embedded_server)
            new LambdaEmbeddedServerFactory(None)
            spark.stop()

    @staticmethod
    def configure_routes():
        init_exception_handler = lambda e: self.assertEqual(TEST_EXCEPTION_MESSAGE, str(e))
        get('/test-route', (req, res) => {
            res.status(200)
            return 'test'
        })

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@Test` and `@AfterClass`. Instead we use the built-in testing framework called `unittest`. The test methods are marked with a prefix (`test_`) to distinguish them from other functions.