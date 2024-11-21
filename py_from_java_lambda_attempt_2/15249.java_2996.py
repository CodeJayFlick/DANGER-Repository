Here is the translation of the Java code to Python:
```
import logging
from typing import AbstractMethodError

class InputParser:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @abstractmethod
    def parse(self) -> None:
        pass

    def handle_payment_intent(self, payment_intent: PaymentIntent) -> None:
        raise NotImplementedError()

    def handle_direct_transaction(self, transaction: Transaction) -> None:
        raise VerificationException("Not implemented")

class StringInputParser(InputParser):
    def __init__(self, input: str):
        self.input = input

    @abstractmethod
    def parse(self) -> None:
        if self.input.startswith("BITCOIN:-"):
            try:
                serialized_payment_request = Qr.decode_binary(self.input[9:])
                self.parse_and_handle_payment_request(serialized_payment_request)
            except (IOException, PaymentProtocolException):
                self.logger.info(f"Error parsing payment request: {self.input}")
                error(R.string.input_parser_io_error)

        elif self.input.startswith("bitcoin:") or self.input.startswith("BITCOIN:"):
            try:
                bitcoin_uri = BitcoinURI(self.input[8:])
                address = bitcoin_uri.get_address()
                if address and not Constants.NETWORK_PARAMETERS.equals(address.parameters):
                    raise BitcoinURIParseException("Mismatched network")
                handle_payment_intent(PaymentIntent.from_bitcoin_uri(bitcoin_uri))
            except (BitcoinURIParseException, AddressFormatException):
                self.logger.info(f"Invalid bitcoin URI: {self.input}")
                error(R.string.input_parser_invalid_bitcoin_uri)

        elif PATTERN_TRANSACTION_BASE43.match(self.input) or PATTERN_TRANSACTION_HEX.match(self.input):
            try:
                transaction = Transaction(Constants.NETWORK_PARAMETERS, Qr.decode_decompress_binary(self.input))
                handle_direct_transaction(transaction)
            except (IOException, ProtocolException):
                self.logger.info(f"Invalid transaction: {self.input}")
                error(R.string.input_parser_invalid_transaction)

        else:
            cannot_classify(self.input)

    def parse_and_handle_payment_request(self, serialized_payment_request: bytes) -> None:
        payment_intent = parse_payment_request(serialized_payment_request)
        handle_payment_intent(payment_intent)

def parse_payment_request(serialized_payment_request: bytes) -> PaymentIntent:
    try:
        if len(serialized_payment_request) > 50000:
            raise PaymentProtocolException("Payment request too big")
        payment_request = Protos.PaymentRequest.parse_from(serialized_payment_request)
        pki_name, pki_ca_name = None, None
        if payment_request.pki_type != "none":
            keystore = TrustStoreLoader.DefaultTrustStoreLoader().get_key_store()
            verification_data = PaymentProtocol.verify_payment_request_pki(payment_request, keystore)
            pki_name, pki_ca_name = verification_data.display_name, verification_data.root_authority_name
        payment_session = PaymentProtocol.parse_payment_request(payment_request)
        if payment_session.is_expired():
            raise PaymentProtocolException.Expired("Payment details expired")
        if not payment_session.network_parameters.equals(Constants.NETWORK_PARAMETERS):
            raise PaymentProtocolException.InvalidNetwork("Cannot handle payment request network")

    except (InvalidProtocolBufferException, UninitializedMessageException) as e:
        raise PaymentProtocolException(e)

class BinaryInputParser(InputParser):
    def __init__(self, input_type: str, input: bytes):
        self.input_type = input_type
        self.input = input

    @abstractmethod
    def parse(self) -> None:
        if self.input_type == Constants.MIMETYPE_TRANSACTION:
            try:
                transaction = Transaction(Constants.NETWORK_PARAMETERS, self.input)
                handle_direct_transaction(transaction)
            except VerificationException as e:
                self.logger.info(f"Invalid transaction: {self.input}")
                error(R.string.input_parser_invalid_transaction)

        elif self.input_type == PaymentProtocol.MIMETYPE_PAYMENTREQUEST:
            try:
                parse_and_handle_payment_request(self.input)
            except (PaymentProtocolException, PkiVerificationException):
                self.logger.info("Unverifyable payment request")
                error(R.string.input_parser_unverifyable_paymentrequest)

        else:
            cannot_classify(self.input_type)

class StreamInputParser(InputParser):
    def __init__(self, input_type: str, is: InputStream):
        self.input_type = input_type
        self.is = is

    @abstractmethod
    def parse(self) -> None:
        if self.input_type == PaymentProtocol.MIMETYPE_PAYMENTREQUEST:
            try:
                with ByteArrayOutputStream() as baos:
                    ByteStreams.copy(is, baos)
                    parse_and_handle_payment_request(baos.toByteArray())
            except (IOException, PaymentProtocolException):
                self.logger.info("Error parsing payment request")
                error(R.string.input_parser_io_error)

        else:
            cannot_classify(self.input_type)

    def handle_direct_transaction(self, transaction: Transaction) -> None:
        raise VerificationException("Not implemented")

def main():
    # Create an instance of the InputParser class
    input_parser = StringInputParser(input)
    input_parser.parse()

if __name__ == "__main__":
    main()
```
Note that I've used Python's built-in `logging` module to handle logging, and also used type hints for method parameters. Additionally, some Java-specific constructs like `@abstractmethod`, `try-catch-finally` blocks, and `raise` statements have been translated into their equivalent Python forms.

Also note that this is a direct translation of the provided code, without any modifications or optimizations specific to Python.