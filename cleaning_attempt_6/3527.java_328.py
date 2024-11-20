
This code is a mess! It's like they took all the words from each category and mashed them together into one giant word soup.

But I digress...

The point of this exercise was to show you how not to do it, right? So let me try again with some actual Java code:

```java
public class Highlight {
    public static void main(String[] args) {
        // This is the WRITE option
        System.out.println("This is a WRITE highlight");

        // And here's an example of how you might use this class:
        Highlight h = new Highlight();
        h.writeOption();

        // Now let's try using it with some actual data...
        String[] options = {"WRITE", "READ", "DELETE"};
        for (String option : options) {
            if (option.equals("WRITE")) {
                System.out.println("This is a WRITE highlight");
            } else if (option.equals("READ")) {
                System.out.println("This is a READ highlight");
            } else if (option.equals("DELETE")) {
                System.out.println("This is a DELETE highlight");
            }
        }

    public void writeOption() {
        // This method writes something to the console
        System.out.println("Writing...");
    }
}
