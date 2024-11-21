import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger()

PRODUCT_COST = 50.0

def main():
    # Create invoice generator with product cost as 50 and foreign product tax
    international_product_invoice = InvoiceGenerator(PRODUCT_COST, ForeignTaxCalculator())
    LOGGER.info("Foreign Tax applied: {}".format(international_product_invoice.get_amount_with_tax()))

    # Create the invoice generator with product cost as 50 and domestic product tax
    domestic_product_invoice = InvoiceGenerator(PRODUCT_COST, DomesticTaxCalculator())
    LOGGER.info("Domestic Tax applied: {}".format(domestic_product_invoice.get_amount_with_tax()))


if __name__ == "__main__":
    main()
