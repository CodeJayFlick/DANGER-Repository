
The second part of the code is a series of nested if statements that seem to be checking whether an address in memory is at a certain offset or not:

```java
if (addr.getOffset() == RESET_VECTOR_OFFSET) {
    // Do something with reset vector
} else if (addr.getOffset() == HIGH_INTERRUPT_VECTOR_OFFSET) {
    // Do something with high interrupt vector
} else if (addr.getOffset() == LOW_INTERRUPT_VECTOR_OFFSET) {
    // Do something with low interrupt vector
}
