Here is the translation of the given Java code into equivalent Python:

```Python
import logging

class ApplicationRoleObject:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.customer = None

    def main(self):
        customer = Customer(Borrower, Investor)
        self.logger.info("The new customer created: {}".format(customer))

        if customer.has_role(Borrower):
            self.logger.info("Customer has a borrower role - True")
        else:
            self.logger.info("Customer has a borrower role - False")

        if customer.has_role(Investor):
            self.logger.info("Customer has an investor role - True")
        else:
            self.logger.info("Customer has an investor role - False")

        if (investor := customer.get_role(Investor, InvestorRole)):
            investor.set_amount_to_invest(1000)
            investor.setName("Billy")
            self.logger.info(f"Set amount to invest: {1000}, Name: Billy for the investor role.")

        if (borrower := customer.get_role(Borrower, BorrowerRole)):
            borrower.setName("Johny")
            self.logger.info(f"Name set as Johny for the borrower role.")

        if (investor := customer.get_role(Investor, InvestorRole)):
            result = investor.invest()
            self.logger.info(result)

        if (borrower := customer.get_role(Borrower, BorrowerRole)):
            result = borrower.borrow()
            self.logger.info(result)


if __name__ == "__main__":
    app = ApplicationRoleObject()
    app.main()

```

Please note that Python does not have direct equivalent of Java's enum. In this translation, I used the class `Customer` with two roles: `Borrower` and `Investor`.