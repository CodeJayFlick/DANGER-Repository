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


public class SBTypeSynthetic {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBTypeSynthetic(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBTypeSynthetic obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  @SuppressWarnings("deprecation")
  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        lldbJNI.delete_SBTypeSynthetic(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBTypeSynthetic() {
    this(lldbJNI.new_SBTypeSynthetic__SWIG_0(), true);
  }

  public static SBTypeSynthetic CreateWithClassName(String data, long options) {
    return new SBTypeSynthetic(lldbJNI.SBTypeSynthetic_CreateWithClassName__SWIG_0(data, options), true);
  }

  public static SBTypeSynthetic CreateWithClassName(String data) {
    return new SBTypeSynthetic(lldbJNI.SBTypeSynthetic_CreateWithClassName__SWIG_1(data), true);
  }

  public static SBTypeSynthetic CreateWithScriptCode(String data, long options) {
    return new SBTypeSynthetic(lldbJNI.SBTypeSynthetic_CreateWithScriptCode__SWIG_0(data, options), true);
  }

  public static SBTypeSynthetic CreateWithScriptCode(String data) {
    return new SBTypeSynthetic(lldbJNI.SBTypeSynthetic_CreateWithScriptCode__SWIG_1(data), true);
  }

  public SBTypeSynthetic(SBTypeSynthetic rhs) {
    this(lldbJNI.new_SBTypeSynthetic__SWIG_1(SBTypeSynthetic.getCPtr(rhs), rhs), true);
  }

  public boolean IsValid() {
    return lldbJNI.SBTypeSynthetic_IsValid(swigCPtr, this);
  }

  public boolean IsEqualTo(SBTypeSynthetic rhs) {
    return lldbJNI.SBTypeSynthetic_IsEqualTo(swigCPtr, this, SBTypeSynthetic.getCPtr(rhs), rhs);
  }

  public boolean IsClassCode() {
    return lldbJNI.SBTypeSynthetic_IsClassCode(swigCPtr, this);
  }

  public String GetData() {
    return lldbJNI.SBTypeSynthetic_GetData(swigCPtr, this);
  }

  public void SetClassName(String data) {
    lldbJNI.SBTypeSynthetic_SetClassName(swigCPtr, this, data);
  }

  public void SetClassCode(String data) {
    lldbJNI.SBTypeSynthetic_SetClassCode(swigCPtr, this, data);
  }

  public long GetOptions() {
    return lldbJNI.SBTypeSynthetic_GetOptions(swigCPtr, this);
  }

  public void SetOptions(long arg0) {
    lldbJNI.SBTypeSynthetic_SetOptions(swigCPtr, this, arg0);
  }

  public boolean GetDescription(SBStream description, DescriptionLevel description_level) {
    return lldbJNI.SBTypeSynthetic_GetDescription(swigCPtr, this, SBStream.getCPtr(description), description, description_level.swigValue());
  }

  public String __str__() {
    return lldbJNI.SBTypeSynthetic___str__(swigCPtr, this);
  }

}
