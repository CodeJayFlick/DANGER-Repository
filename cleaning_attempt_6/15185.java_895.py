import bitcoinj.core as bc
from bitcoinj.script import ScriptBuilder
from bitcoinj.protocols.payments import Protos
from bitcoinj.utils import NetworkParameters

class SampleActivity:
    AMOUNT = 500000
    DONATION_ADDRESSES_MAINNET = ["18CK5k1gajRKKSC7yVSTXT9LUzbheh1XY4", "1PZmMahjbfsTy6DsaRyfStzoWTPppWwDnZ"]
    DONATION_ADDRESSES_TESTNET = ["mkCLjaXncyw8eSWJBcBtnTgviU85z5PfwS", "mwEacn7pYszzxfgcNaVUzYvzL6ypRJzB6A"]
    MEMO = "Sample donation"
    REQUEST_CODE = 0

    def __init__(self):
        self.donate_button = None
        self.request_button = None
        self.donate_message = None

    def onCreate(self, savedInstanceState):
        super().__init__()
        self.setContentView(R.layout.sample_activity)

        self.donate_button = findViewById(R.id.sample_donate_button)
        self.donate_button.setOnClickListener(lambda v: self.handleDonate())

        self.request_button = findViewById(R.id.sample_request_button)
        self.request_button.setOnClickListener(lambda v: self.handleRequest())

        self.donate_message = findViewById(R.id.sample_donate_message)

    def donation_addresses(self):
        is_mainnet = (self.findViewById(R.id.sample_network_mainnet)).isChecked()
        return DONATION_ADDRESSES_MAINNET if is_mainnet else DONATION_ADDRESSES_TESTNET

    def handleDonate(self):
        addresses = self.donation_addresses()
        BitcoinIntegration.requestForResult(REQUEST_CODE, [addresses[0]])

    def handleRequest(self):
        try:
            addresses = self.donation_addresses()
            params = bc.Address.get_parameters_from_address(addresses[0])

            output1 = Protos.Output.newBuilder().set_amount(self.AMOUNT).set_script(bc.ScriptBuilder.create_output_script(bc.Address(params, addresses[0])).get_program())
            output2 = Protos.Output.newBuilder().set_amount(self.AMOUNT).set_script(bc.ScriptBuilder.create_output_script(bc.Address(params, addresses[1])).get_program())

            payment_details = Protos.PaymentDetails.newBuilder()
            payment_details.set_network(params.get_payment_protocol_id()).add_outputs(output1).add_outputs(output2)
            payment_details.set_memo(self.MEMO).set_time(int(time.time()))

            payment_request = Protos.PaymentRequest.newBuilder().set_serialized_payment_details(payment_details.build().to_byte_string())
            BitcoinIntegration.requestForResult(REQUEST_CODE, [payment_request.build().to_bytes()])

        except bc.AddressFormatException as x:
            raise Exception(x)

    def onActivityResult(self, requestCode, resultCode, data):
        if requestCode == self.REQUEST_CODE:
            if resultCode == 0: # Activity.RESULT_OK
                tx_hash = BitcoinIntegration.transaction_hash_from_result(data)
                if tx_hash is not None:
                    message_builder = SpannableStringBuilder("Transaction hash:\n")
                    message_builder.append(tx_hash)
                    message_builder.set_span(TypefaceSpan('monospace'), len(message_builder) - len(tx_hash), 
                                               len(message_builder), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)

                    if BitcoinIntegration.payment_from_result(data):
                        message_builder.append("\n(also a BIP70 payment message was received)")

                    self.donate_message.setText(message_builder)
                    self.donate_message.setVisibility(View.VISIBLE)

                Toast.makeText(self, "Thank you!", Toast.LENGTH_LONG).show()

            elif resultCode == 1: # Activity.RESULT_CANCELED
                Toast.makeText(self, "Cancelled.", Toast.LENGTH_LONG).show()
            else:
                Toast.makeText(self, "Unknown result.", Toast.LENGTH_LONG).show()
