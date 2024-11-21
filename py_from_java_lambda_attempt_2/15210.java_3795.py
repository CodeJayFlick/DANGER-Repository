Here is a translation of your Java code into Python:

```Python
import logging
from bluetooth import BluetoothSocket, BluetoothServerSocket
from bitcoinj.core import Context
from slf4j import LoggerFactory

class AcceptBluetoothThread:
    def __init__(self, listening_socket):
        self.listening_socket = listening_socket
        self.running = True

    @property
    def logger(self):
        return logging.getLogger(__name__)

    def run(self):
        while self.running:
            try:
                socket = self.listening_socket.accept()
                input_stream = socket.makefile('rb')
                output_stream = socket.makefile('wb')

                if not self.handle_connection(input_stream, output_stream):
                    break

            except Exception as e:
                self.logger.info("exception in bluetooth accept loop", e)

        try:
            self.listening_socket.close()
        except Exception as e:
            pass  # swallow the exception

    def stop_accepting(self):
        self.running = False
        try:
            self.listening_socket.close()
        except Exception as e:
            pass  # swallow the exception

class ClassicBluetoothThread(AcceptBluetoothThread):
    def __init__(self, adapter):
        super().__init__(adapter.listen(1))

    def handle_connection(self, input_stream, output_stream):
        num_messages = int.from_bytes(input_stream.read(4), 'big')
        for _ in range(num_messages):
            msg_length = int.from_bytes(input_stream.read(4), 'big')
            message = bytearray(msg_length)
            input_stream.readinto(message)

            try:
                transaction = Transaction(Constants.NETWORK_PARAMETERS, bytes(message))
                if not self.handle_tx(transaction):
                    return False
            except Exception as e:
                self.logger.info("cannot decode message received via bluetooth", e)
                return False

        output_stream.write(b'\x01')  # ack
        return True


class PaymentProtocolThread(AcceptBluetoothThread):
    def __init__(self, adapter):
        super().__init__(adapter.listen(1))

    def handle_connection(self, input_stream, output_stream):
        payment = Protos.Payment()
        payment.ParseFromString(input_stream.read())

        for transaction in PaymentProtocol.parse_transactions(payment):
            if not self.handle_tx(transaction):
                return False

        memo = "ack"  # or "nack"
        payment_ack = PaymentProtocol.create_payment_ack(payment, memo)
        output_stream.write(payment_ack.SerializeToString())
        return True
```

This Python code is a direct translation of your Java code. It uses the `bluetooth` and `slf4j` libraries to handle Bluetooth connections and logging respectively. The rest of the logic remains the same as in your original Java code.

Please note that you will need to install these libraries using pip:

```
pip install pybluez
pip install logbook
```