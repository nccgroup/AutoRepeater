package burp;

import java.util.List;
import java.util.Map;

/**
 * Created by j on 2/8/18.
 */

//TODO: Wrap bayou's multipart form parsing here.
public class MultipartFormDataRequest {

  List<String> headers;


  // Need to check and make sure a request is a multipart form before creating
  public static boolean isRequestMultipartForm(byte[] request) {
    IExtensionHelpers helpers = BurpExtender.getHelpers();
    IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
    List<String> headers = analyzedRequest.getHeaders();
    return headers.stream().anyMatch((h) -> h.startsWith("Content-Type: multipart/form-data;"));
  }

  private String getBoundary(byte[] request) {
    return "";
  }

  public class MultipartFormPart {
    // Iunno if a list or map is better here
    Map<String,String> headers;
    byte[] body;
  }

}
