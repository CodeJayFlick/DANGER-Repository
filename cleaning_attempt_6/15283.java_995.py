import logging
from typing import Optional

class RequestPaymentRequestTask:
    def __init__(self, background_handler: 'Handler', result_callback: 'ResultCallback'):
        self.background_handler = background_handler
        self.callback_handler = Handler(Looper.my_looper())
        self.result_callback = result_callback

    @property
    def logger(self):
        return logging.getLogger(type(self).__name__)

class ResultCallback:
    def on_payment_intent(self, payment_intent: 'PaymentIntent'):
        pass

    def on_fail(self, message_res_id: int, *message_args) -> None:
        pass


class HttpRequestTask(RequestPaymentRequestTask):
    def __init__(self, background_handler: 'Handler', result_callback: 'ResultCallback',
                 user_agent: Optional[str] = None):
        super().__init__(background_handler, result_callback)
        self.user_agent = user_agent

    def request_payment_request(self, url: str) -> None:
        self.background_handler.post(lambda: self._request_payment_request(url))

    def _request_payment_request(self, url: str) -> None:
        logging.info("trying to request payment request from %s", url)

        request_builder = Request.Builder()
        request_builder.url(url)
        request_builder.cache_control(CacheControl().no_cache())
        headers = Headers.build()
        if self.user_agent is not None:
            headers.add('User-Agent', self.user_agent)
        request_builder.headers(headers.build())

        call = Constants.HTTP_CLIENT.new_call(request_builder.build())
        try:
            response = call.execute()
            if response.is_successful():
                content_type = response.header('Content-Type')
                input_parser = InputParser.StreamInputParser(content_type, response.body().byte_stream())
                payment_intent = None
                for line in input_parser.parse():
                    if PaymentProtocol.MIMETYPE_PAYMENTREQUEST == line:
                        payment_intent = PaymentIntent(line)
                        break

                self.on_payment_intent(payment_intent)

            else:
                logging.info("got http error %d: %s", response.code(), response.message())
                self.on_fail(R.string.error_http, response.code(), response.message())

        except IOException as e:
            logging.info("problem sending", e)
            self.on_fail(R.string.error_io, str(e))

class BluetoothRequestTask(RequestPaymentRequestTask):
    def __init__(self, background_handler: 'Handler', result_callback: 'ResultCallback',
                 bluetooth_adapter: 'BluetoothAdapter'):
        super().__init__(background_handler, result_callback)
        self.bluetooth_adapter = bluetooth_adapter

    def request_payment_request(self, url: str) -> None:
        self.background_handler.post(lambda: self._request_payment_request(url))

    def _request_payment_request(self, url: str) -> None:
        logging.info("trying to request payment request from %s", url)

        device = self.bluetooth_adapter.get_remote_device(Bluetooth.decompress_mac(
            Bluetooth.get_bluetooth_mac(url)))

        try:
            with socket.create_insecure_rfcomm_socket_to_service_record(device,
                                                                        Bluetooth.PAYMENT_REQUESTS_UUID) as sock:
                sock.connect()
                logging.info("connected to %s", url)

                cis = CodedInputStream(sock.getInputStream())
                cos = CodedOutputStream(sock.getOutputStream())

                cos.write_int32_no_tag(0)
                cos.write_string_no_tag(Bluetooth.get_bluetooth_query(url))
                cos.flush()

                response_code = cis.read_int32()
                if 200 == response_code:
                    payment_intent = None
                    for line in InputParser.BinaryInputParser(
                            PaymentProtocol.MIMETYPE_PAYMENTREQUEST, cis.read_bytes().to_byte_array()):
                        if PaymentProtocol.MIMETYPE_PAYMENTREQUEST == line:
                            payment_intent = PaymentIntent(line)
                            break

                    self.on_payment_intent(payment_intent)

                else:
                    logging.info("got bluetooth error %d", response_code)
                    self.on_fail(R.string.error_bluetooth, response_code)

        except IOException as e:
            logging.info("problem sending", e)
            self.on_fail(R.string.error_io, str(e))
