package burp.Utils;

import burp.IHttpListener;
import burp.IHttpRequestResponse;
import java.util.HashMap;
import java.util.Set;
import java.util.stream.Collectors;

// This will allow AutoRepeater to replace values in Requests based on previous responses from domains
// This will be its own HTTPListener to keep track of all requests, not just the one's AutoRepeater sends
// The Data store should be something along the lines of a Map of some storage object which holds the timestamp + RequestResponse
// and the key being the domain. It might make sense to use the full path instead of just the URL.
// TODO: Move this idea into a new plugin.
public class ResponseStore implements IHttpListener {

  // Container class for the response body + time it was received
  public class Response {
    byte[] responseBody;
    long time;

    public Response(byte[] responseBody) {
      time = System.currentTimeMillis();
      this.responseBody = responseBody;
    }
  }

  // Hashmap to store responses and their URL
  private HashMap<String, Response> responseHashMap;

  public ResponseStore() {
    responseHashMap = new HashMap<>();
  }

  public byte[] getMostRecentResponseBodyByRegex (String urlRegex)  {
    // Get all the keys that match the regex
    Set<String> matchingUrls = responseHashMap.keySet()
        .stream()
        .filter(key -> key.matches(urlRegex))
        .collect(Collectors.toSet());
    // Get an element from the hashmap to start from, it doesn't matter which element
    Response mostRecentResponse = responseHashMap.get(matchingUrls.iterator().next());
    // Iterate over the matching url responses to find the most recent one
    for (String matchingUrl : matchingUrls) {
      Response tempResponse = responseHashMap.get(matchingUrl);
      if (mostRecentResponse.time < tempResponse.time) {
        mostRecentResponse = tempResponse;
      }
    }
    return mostRecentResponse.responseBody;
  }

  public byte[] getMostRecentResponseBody (String url) {
    return responseHashMap.get(url).responseBody;
  }

  @Override
  public void processHttpMessage(int toolFlag, boolean messageIsRequest,
      IHttpRequestResponse messageInfo) {
    if (!messageIsRequest) {
      // Add the response body to the hashmap
      responseHashMap.put(messageInfo.getHttpService().getHost(), new Response(messageInfo.getResponse()));
    }
  }
}
