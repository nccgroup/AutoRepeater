package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by j on 2/8/18.
 */

//TODO: Wrap bayou's multipart form parsing here.
public class MultipartFormDataRequest {
  private final static Pattern multipartTypeRegex = Pattern.compile("Content-Type: multipart/[^;]*;");
  // The type of multipart request this is. Will probably always be multipart/form but could be something else
  String multipartType;
  // The boundary value
  String boundary;
  List<String> headers;


  public MultipartFormDataRequest(byte[] request) {
    // Need to make sure this is multipart just in case
    if (isRequestMultipartForm(request)) {
      IExtensionHelpers helpers = BurpExtender.getHelpers();
      IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
      List<String> headers = analyzedRequest.getHeaders();
      for (String header : headers) {
        if (getMultipartType(header) != null) {
          multipartType = getMultipartType(header);
        }
      }
      if (multipartType != null) {
        boundary = getBoundaryFromRequest(request, multipartType);
      }
    }
  }

  // Need to check and make sure a request is a multipart form before creating
  public static boolean isRequestMultipartForm(byte[] request) {
    IExtensionHelpers helpers = BurpExtender.getHelpers();
    IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
    List<String> headers = analyzedRequest.getHeaders();
    for (String header : headers) {
      if(getMultipartType(header) != null) {
        return true;
      }
    }
    return false;
  }

  private static String getMultipartType(String header) {
    Matcher multipartMatcher = multipartTypeRegex.matcher(header);
    if (multipartMatcher.find()) {
      return multipartMatcher.group();
    } else {
      return null;
    }
  }

  // This should probably return an exception instead of null
  private String getBoundaryFromRequest(byte[] request, String multipartType) {
    IExtensionHelpers helpers = BurpExtender.getHelpers();
    IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
    List<String> headers = analyzedRequest.getHeaders();
    for (String header : headers) {
      // This should probably check for "Content-Type: multipart/"
      if(header.startsWith(multipartType)) {
        String boundary = Utils.getStringAfterSubstring(header, "boundary=").trim();
        if (boundary.charAt(0) == '"' && boundary.charAt(boundary.length()-1) == '"') {
          return boundary.substring(1, boundary.length()-1);
        } else {
          return boundary;
        }
      }
    }
    return null;
  }

  public class MultipartFormPart {
    // Iunno if a list or map is better here
    private ArrayList<String> headers;
    private byte[] body;
  }

}
