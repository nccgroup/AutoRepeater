package burp.Logs;

import burp.BurpExtender;
import burp.IHttpRequestResponsePersisted;
import burp.IRequestInfo;
import burp.IResponseInfo;
import java.net.URL;
import java.util.Arrays;

public class LogEntry {

  private long requestResponseId;
  private IHttpRequestResponsePersisted originalRequestResponse;
  private IHttpRequestResponsePersisted modifiedRequestResponse;

  private URL originalURL;
  private URL modifiedURL;

  private String originalMethod;
  private String modifiedMethod;

  private int originalLength;
  private int modifiedLength;
  private int lengthDifference;
  private double responseDistance;

  private int originalResponseStatus;
  private int modifiedResponseStatus;

  private int originalRequestHashCode;
  private int modifiedRequestHashCode;

  private int toolFlag;

  private long requestSentTime;

  public long getRequestResponseId() {
    return requestResponseId;
  }

  public void setRequestResponseId(long requestResponseId) {
    this.requestResponseId = requestResponseId;
  }

  public IHttpRequestResponsePersisted getOriginalRequestResponse() {
    return originalRequestResponse;
  }

  public void setOriginalRequestResponse(IHttpRequestResponsePersisted originalRequestResponse) {
    this.originalRequestResponse = originalRequestResponse;
  }

  public IHttpRequestResponsePersisted getModifiedRequestResponse() {
    return modifiedRequestResponse;
  }

  public void setModifiedRequestResponse(IHttpRequestResponsePersisted modifiedRequestResponse) {
    this.modifiedRequestResponse = modifiedRequestResponse;
  }

  public URL getOriginalURL() {
    return originalURL;
  }

  public void setOriginalURL(URL originalURL) {
    this.originalURL = originalURL;
  }

  public URL getModifiedURL() {
    return modifiedURL;
  }

  public void setModifiedURL(URL modifiedURL) {
    this.modifiedURL = modifiedURL;
  }

  public int getOriginalRequestHashCode() {
    return originalRequestHashCode;
  }

  public int getModifiedRequestHashCode() {
    return modifiedRequestHashCode;
  }

  public long getRequestSentTime() {
    return requestSentTime;
  }

  public String getOriginalMethod() {
    return originalMethod;
  }

  public void setOriginalMethod(String originalMethod) {
    this.originalMethod = originalMethod;
  }

  public String getModifiedMethod() {
    return modifiedMethod;
  }

  public void setModifiedMethod(String modifiedMethod) {
    this.modifiedMethod = modifiedMethod;
  }

  public int getOriginalLength() {
    return originalLength;
  }

  public void setOriginalLength(int originalLength) {
    this.originalLength = originalLength;
  }

  public int getModifiedLength() {
    return modifiedLength;
  }

  public void setModifiedLength(int modifiedLength) {
    this.modifiedLength = modifiedLength;
  }

  public int getLengthDifference() {
    return lengthDifference;
  }

  public void setLengthDifference(int lengthDifference) {
    this.lengthDifference = lengthDifference;
  }

  public double getResponseDistance() {
    return responseDistance;
  }

  public void setResponseDistance(double responseDistance) {
    this.responseDistance = responseDistance;
  }

  public int getOriginalResponseStatus() {
    return originalResponseStatus;
  }

  public void setOriginalResponseStatus(int originalResponseStatus) {
    this.originalResponseStatus = originalResponseStatus;
  }

  public int getModifiedResponseStatus() {
    return modifiedResponseStatus;
  }

  public void setModifiedResponseStatus(int modifiedResponseStatus) {
    this.modifiedResponseStatus = modifiedResponseStatus;
  }

  public void setOriginalRequestHashCode(int originalRequestHashCode) {
    this.originalRequestHashCode = originalRequestHashCode;
  }

  public void setModifiedRequestHashCode(int modifiedRequestHashCode) {
    this.modifiedRequestHashCode = modifiedRequestHashCode;
  }

  public void setRequestSentTime(long requestSentTime) {
    this.requestSentTime = requestSentTime;
  }

  //#, Host, Method, URL, Status, Length
  // #
  // Host
  // Orig. Method
  // Mod. Method
  // Orig. URL
  // Mod. URL
  // Orig. Status
  // Mod. Status
  // Orig. Length
  // Mod. Length

  public LogEntry(long requestResponseId,
      int toolFlag,
      IHttpRequestResponsePersisted originalRequestResponse,
      IHttpRequestResponsePersisted modifiedRequestResponse) {

    IRequestInfo originalAnalyzedRequest = BurpExtender.getHelpers()
        .analyzeRequest(originalRequestResponse);
    IRequestInfo modifiedAnalyzedRequest = BurpExtender.getHelpers()
        .analyzeRequest(modifiedRequestResponse);

    IResponseInfo originalAnalyzedResponse = BurpExtender.getHelpers()
        .analyzeResponse(originalRequestResponse.getResponse());
    IResponseInfo modifiedAnalyzedResponse = BurpExtender.getHelpers()
        .analyzeResponse(modifiedRequestResponse.getResponse());

    // Request ID
    this.requestResponseId = requestResponseId;

    // Original Request Info
    this.originalRequestResponse = originalRequestResponse;
    this.originalURL = originalAnalyzedRequest.getUrl();
    this.originalMethod = originalAnalyzedRequest.getMethod();
    this.originalResponseStatus = originalAnalyzedResponse.getStatusCode();
    this.originalLength = originalRequestResponse.getResponse().length;

    // Modified Request Info
    this.modifiedRequestResponse = modifiedRequestResponse;
    this.modifiedURL = modifiedAnalyzedRequest.getUrl();
    this.modifiedMethod = modifiedAnalyzedRequest.getMethod();
    this.modifiedResponseStatus = modifiedAnalyzedResponse.getStatusCode();
    this.modifiedLength = modifiedRequestResponse.getResponse().length;

    // Comparisons
    this.lengthDifference = Math.abs(this.originalLength - this.modifiedLength);
    this.responseDistance = 0;

    this.originalRequestHashCode = Arrays.hashCode(originalRequestResponse.getRequest());
    this.modifiedRequestHashCode = Arrays.hashCode(modifiedRequestResponse.getRequest());

    this.toolFlag = toolFlag;

    this.requestSentTime = System.currentTimeMillis();
  }

  public int getToolFlag() {
    return toolFlag;
  }

  public void setToolFlag(int toolFlag) {
    this.toolFlag = toolFlag;
  }
}

