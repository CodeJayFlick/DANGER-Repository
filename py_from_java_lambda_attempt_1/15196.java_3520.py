Here is the translation of the Java code into Python:

```Python
import base64
from typing import List, Optional

class PaymentIntent:
    class Standard(enum.Enum):
        BIP21 = 1
        BIP70 = 2

    def __init__(self,
                 standard: Optional[Standard] = None,
                 payee_name: str = '',
                 payee_verified_by: str = '',
                 outputs: List['Output'] = [],
                 memo: str = '',
                 payment_url: str = '',
                 payee_data: bytes = b'',
                 payment_request_url: str = '',
                 payment_request_hash: bytes = b''):
        self.standard = standard
        self.payee_name = payee_name
        self.payee_verified_by = payee_verified_by
        self.outputs = outputs
        self.memo = memo
        self.payment_url = payment_url
        self.payee_data = payee_data
        self.payment_request_url = payment_request_url
        self.payment_request_hash = payment_request_hash

    @classmethod
    def blank(cls) -> 'PaymentIntent':
        return PaymentIntent()

    @classmethod
    def from_address(cls, address: str, label: Optional[str] = None) -> 'PaymentIntent':
        if not address:
            raise ValueError('Address is required')
        try:
            addr = Address.from_string(address)
        except Exception as e:
            raise ValueError(f'Invalid address {address}: {e}')
        return PaymentIntent(standard=PaymentIntent.Standard.BIP21, payee_name=label)

    @classmethod
    def from_bitcoin_uri(cls, bitcoin_uri: 'BitcoinURI') -> 'PaymentIntent':
        addr = bitcoin_uri.get_address()
        outputs = []
        if addr:
            amount = bitcoin_uri.get_amount()
            script = ScriptBuilder.create_output_script(addr)
            outputs.append(Output(amount, script))
        return PaymentIntent(standard=PaymentIntent.Standard.BIP21,
                              payee_name=None,
                              payee_verified_by=None,
                              outputs=outputs,
                              memo=bitcoin_uri.get_label(),
                              payment_url=bitcoin_uri.get_payment_request_url(),
                              payee_data=None,
                              payment_request_url=None,
                              payment_request_hash=None)

    def merge_with_edited_values(self, edited_amount: Optional[Coin] = None, edited_address: str = '') -> 'PaymentIntent':
        if not self.has_outputs():
            return PaymentIntent(standard=self.standard,
                                  payee_name=self.payee_name,
                                  payee_verified_by=self.payee_verified_by,
                                  outputs=[Output(edited_amount or Coin.ZERO, ScriptBuilder.create_output_script(Address.from_string(edited_address)))],
                                  memo=self.memo,
                                  payment_url=None,
                                  payee_data=self.payee_data,
                                  payment_request_url=None,
                                  payment_request_hash=None)
        if self.has_outputs() and not edited_amount:
            return PaymentIntent(standard=self.standard,
                                  payee_name=self.payee_name,
                                  payee_verified_by=self.payee_verified_by,
                                  outputs=[Output(self.get_amount(), script) for output, script in zip(self.outputs, [script for _, script in self.outputs])],
                                  memo=self.memo,
                                  payment_url=None,
                                  payee_data=self.payee_data,
                                  payment_request_url=None,
                                  payment_request_hash=None)
        return PaymentIntent(standard=self.standard,
                              payee_name=self.payee_name,
                              payee_verified_by=self.payee_verified_by,
                              outputs=[Output(edited_amount, script) for output, script in zip(self.outputs, [script for _, script in self.outputs])],
                              memo=self.memo,
                              payment_url=None,
                              payee_data=self.payee_data,
                              payment_request_url=None,
                              payment_request_hash=None)

    def to_send_request(self) -> 'SendRequest':
        tx = Transaction()
        for output in self.outputs:
            if output.amount > 0:
                tx.add_output(output.amount, output.script)
        return SendRequest(tx)

    @classmethod
    def is_extended_by(cls, other: 'PaymentIntent') -> bool:
        if cls.Standard.BIP21 == other.standard and PaymentIntent.Standard.BIP70 == self.standard:
            return True
        return self.equals_amount(other) and self.equals_address(other)

    def equals_amount(self, other: 'PaymentIntent') -> bool:
        has_amount = self.has_outputs()
        if not has_amount or not other.has_outputs():
            return False
        for output in zip(self.outputs, other.outputs):
            if (output[0].amount != output[1].amount).signum() > 0:
                return False
        return True

    def equals_address(self, other: 'PaymentIntent') -> bool:
        has_address = self.has_outputs()
        if not has_address or not other.has_outputs():
            return False
        for output in zip(self.outputs, other.outputs):
            addr1 = WalletUtils.get_to_address(output[0].script)
            addr2 = WalletUtils.get_to_address(output[1].script)
            if (addr1 != addr2).signum() > 0:
                return False
        return True

    def __str__(self) -> str:
        builder = StringBuilder()
        builder.append(self.__class__.__name__)
        builder.append('[')
        builder.append(str(self.standard))
        builder.append(',')
        if self.has_payee():
            builder.append(self.payee_name)
            if self.payee_verified_by:
                builder.append('/')
                builder.append(self.payee_verified_by)
            builder.append(',')
        builder.append(str(len(self.outputs)) if self.has_outputs() else 'null')
        builder.append(',')
        builder.append(self.payment_url)
        if self.payee_data:
            builder.append(',payeeData=')
            builder.append(base64.b64encode(self.payee_data).decode())
        if self.payment_request_url:
            builder.append(',paymentRequestUrl=')
            builder.append(self.payment_request_url)
        if self.payment_request_hash:
            builder.append(',paymentRequestHash=')
            builder.append(base64.b64encode(self.payment_request_hash).decode())
        builder.append(']')
        return builder.toString()

    def __eq__(self, other: 'PaymentIntent') -> bool:
        if not isinstance(other, PaymentIntent):
            return False
        return self.standard == other.standard and \
               self.payee_name == other.payee_name and \
               self.payee_verified_by == other.payee_verified_by and \
               (not self.has_outputs() or len(self.outputs) == 0 and len(other.outputs) == 0) or \
               ((self.has_outputs() and other.has_outputs()) and
                all(output1 == output2 for output1, output2 in zip(self.outputs, other.outputs))) and \
               self.memo == other.memo and \
               self.payment_url == other.payment_url and \
               (not self.payee_data or not other.payee_data) or \
               ((self.has_payee_data() and other.has_payee_data()) and
                all(byte1 == byte2 for byte1, byte2 in zip(self.payee_data, other.payee_data))) and \
               self.payment_request_url == other.payment_request_url and \
               (not self.payment_request_hash or not other.payment_request_hash) or \
               ((self.has_payment_request_hash() and other.has_payment_request_hash()) and
                all(byte1 == byte2 for byte1, byte2 in zip(self.payment_request_hash, other.payment_request_hash)))

    def __getstate__(self):
        return self.__dict__

    @classmethod
    def create_from.Parcel(cls, parcel: Parcel) -> 'PaymentIntent':
        standard = parcel.readSerializable()
        payee_name = parcel.readString()
        payee_verified_by = parcel.readString()
        outputs_length = parcel.readInt()
        if outputs_length > 0:
            outputs = [Output(parcel) for _ in range(outputs_length)]
        else:
            outputs = None
        memo = parcel.readString()
        payment_url = parcel.readString()
        payee_data_length = parcel.readInt()
        if payee_data_length > 0:
            payee_data = bytearray(payee_data_length)
            parcel.readByteArray(payee_data)
        else:
            payee_data = None
        payment_request_url = parcel.readString()
        payment_request_hash_length = parcel.readInt()
        if payment_request_hash_length > 0:
            payment_request_hash = bytearray(payment_request_hash_length)
            parcel.readByteArray(payment_request_hash)
        else:
            payment_request_hash = None
        return PaymentIntent(standard, payee_name, payee_verified_by, outputs, memo,
                              payment_url, payee_data, payment_request_url, payment_request_hash)

    @classmethod
    def create_from.Parcel_array(cls, parcel: Parcel) -> List['PaymentIntent']:
        length = parcel.readInt()
        result = []
        for _ in range(length):
            result.append(PaymentIntent.create_from.Parcel(parcel))
        return result

class Output:
    def __init__(self, amount: Optional[Coin] = None, script: Script = None):
        self.amount = amount
        self.script = script

    @classmethod
    def value_of(cls, output: 'PaymentProtocol.Output') -> 'Output':
        try:
            return cls(amount=output.amount, script=Script(output.script_data))
        except Exception as e:
            raise PaymentProtocolException.InvalidOutputs(f'unparseable script in output: {Constants.HEX.encode(output.script_data)}')

    def has_amount(self) -> bool:
        return self.amount.signum() != 0

    @classmethod
    def build_simple_pay_to(cls, amount: Coin, address: Address) -> List['Output']:
        return [cls(amount=amount, script=ScriptBuilder.create_output_script(address))]
```

Please note that the translation is not perfect and some parts might be missing or incorrect.