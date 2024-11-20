import unittest
from aws_proxy_request import AwsProxyRequest
from aws_proxy_response import AwsProxyResponse
from aws_lambda_runtime_context import Context
from aws_http_request import HttpServletRequest
from aws_http_response import HttpServletResponse

class MockLambdaContext:
    def __init__(self):
        pass

class MockContainerHandler:
    def __init__(self):
        self.desired_status = 200
        self.response = None
        self.selected_servlet = None

    def get_container_response(self, request, latch):
        return HttpServletResponse(request, latch)

    def do_filter(self, request, response, servlet) -> None:
        self.selected_servlet = servlet
        try:
            self.response = response
            # handle_request((AwsProxyHttpServletRequest)request, , MockLambdaContext())
            if isinstance(request, AwsProxyRequest):
                (request).set_response((self.response))
            self.response.set_status(self.desired_status)
            self.response.flush_buffer()
        except Exception as e:
            raise ServletException(e)

    def set_desired_status(self, status: int) -> None:
        self.desired_status = status

    def get_response(self):
        return self.response

    def get_selected_servlet(self):
        return self.selected_servlet


class AwsAsyncContextTest(unittest.TestCase):

    @unittest.skip
    def test_dispatch_sends_to_correct_servlet(self):
        lambda_ctx = MockLambdaContext()
        handler = MockContainerHandler()
        reader = AwsProxyHttpServletRequestReader()

        req1 = AwsProxyRequestBuilder("/srv1/hello", "GET").build(AwsProxyRequest)
        req2 = AwsProxyRequestBuilder("/srv5/hello", "GET").build(AwsProxyRequest)

        req1.set_response(handler.get_container_response(req1, CountDownLatch(1)))
        req1.set_servlet_context(None)
        req1.set_container_handler(handler)

        async_ctx = req1.start_async()
        handler.set_desired_status(201)
        async_ctx.dispatch()
        self.assertIsNotNone(handler.get_selected_servlet())
        self.assertEqual(srv1, handler.get_selected_servlet())
        self.assertEqual(201, handler.get_response().get_status())

        req2.set_response(handler.get_container_response(req2, CountDownLatch(1)))
        req2.set_servlet_context(None)
        req2.set_container_handler(handler)

        async_ctx = req2.start_async()
        handler.set_desired_status(202)
        async_ctx.dispatch()
        self.assertIsNotNone(handler.get_selected_servlet())
        self.assertEqual(srv2, handler.get_selected_servlet())
        self.assertEqual(202, handler.get_response().get_status())

    @unittest.skip
    def test_dispatch_new_path_sends_to_correct_servlet(self):
        req = reader.read_request(AwsProxyRequestBuilder("/srv1/hello", "GET").build(), None, lambda_ctx)
        req.set_response(handler.get_container_response(req, CountDownLatch(1)))
        req.set_servlet_context(None)
        req.set_container_handler(handler)

        async_ctx = req.start_async()
        handler.set_desired_status(301)
        async_ctx.dispatch("/srv4/hello")
        self.assertIsNotNone(handler.get_selected_servlet())
        self.assertEqual(srv2, handler.get_selected_servlet())
        self.assertIsNotNone(handler.get_response())
        self.assertEqual(301, handler.get_response().get_status())

    def get_ctx(self):
        ctx = AwsServletContext()
        handler.set_servlet_context(ctx)

        reg1 = ctx.add_servlet("srv1", srv1)
        reg1.add_mapping("/srv1")

        reg2 = ctx.add_servlet("srv2", srv2)
        reg2.add_mapping("/")
        return ctx


if __name__ == '__main__':
    unittest.main()
