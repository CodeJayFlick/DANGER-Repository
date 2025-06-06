/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
package SWIG;


/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */


public final class ConnectionStatus {
  public final static ConnectionStatus eConnectionStatusSuccess = new ConnectionStatus("eConnectionStatusSuccess");
  public final static ConnectionStatus eConnectionStatusEndOfFile = new ConnectionStatus("eConnectionStatusEndOfFile");
  public final static ConnectionStatus eConnectionStatusError = new ConnectionStatus("eConnectionStatusError");
  public final static ConnectionStatus eConnectionStatusTimedOut = new ConnectionStatus("eConnectionStatusTimedOut");
  public final static ConnectionStatus eConnectionStatusNoConnection = new ConnectionStatus("eConnectionStatusNoConnection");
  public final static ConnectionStatus eConnectionStatusLostConnection = new ConnectionStatus("eConnectionStatusLostConnection");
  public final static ConnectionStatus eConnectionStatusInterrupted = new ConnectionStatus("eConnectionStatusInterrupted");

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static ConnectionStatus swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
    for (int i = 0; i < swigValues.length; i++)
      if (swigValues[i].swigValue == swigValue)
        return swigValues[i];
    throw new IllegalArgumentException("No enum " + ConnectionStatus.class + " with value " + swigValue);
  }

  private ConnectionStatus(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private ConnectionStatus(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private ConnectionStatus(String swigName, ConnectionStatus swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static ConnectionStatus[] swigValues = { eConnectionStatusSuccess, eConnectionStatusEndOfFile, eConnectionStatusError, eConnectionStatusTimedOut, eConnectionStatusNoConnection, eConnectionStatusLostConnection, eConnectionStatusInterrupted };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

