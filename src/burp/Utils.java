package burp;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.*;
import java.awt.*;
import java.util.List;

public class Utils {

  public static String exportLogEntriesToJson (ArrayList<LogEntry> logEntries, boolean exportHttp) {
    JsonArray json = new JsonArray();
    if(exportHttp) {
      for (LogEntry log : logEntries) {
        JsonObject logJson = new JsonObject();
        logJson.addProperty("#",log.getRequestResponseId());
        logJson.addProperty("Method",log.getModifiedMethod());
        logJson.addProperty("URL",log.getModifiedURL().toString());
        logJson.addProperty("Orig. Status",log.getOriginalResponseStatus());
        logJson.addProperty("Status",log.getModifiedResponseStatus());
        logJson.addProperty("Orig. Resp. Len.",log.getOriginalLength());
        logJson.addProperty("Resp. Len.",log.getModifiedLength());
        logJson.addProperty("Resp. Len. Diff.",log.getLengthDifference());
        logJson.addProperty("Orig. Request",new String(log.getOriginalRequestResponse().getRequest()));
        logJson.addProperty("Orig. Response",new String(log.getOriginalRequestResponse().getResponse()));
        logJson.addProperty("Request",new String(log.getModifiedRequestResponse().getRequest()));
        logJson.addProperty("Response",new String(log.getModifiedRequestResponse().getResponse()));
        json.add(logJson);

      }
    } else {
      for (LogEntry log : logEntries) {
        JsonObject logJson = new JsonObject();
        logJson.addProperty("#",log.getRequestResponseId());
        logJson.addProperty("Method",log.getModifiedMethod());
        logJson.addProperty("URL",log.getModifiedURL().toString());
        logJson.addProperty("Orig. Status",log.getOriginalResponseStatus());
        logJson.addProperty("Status",log.getModifiedResponseStatus());
        logJson.addProperty("Orig. Resp. Len.",log.getOriginalLength());
        logJson.addProperty("Resp. Len.",log.getModifiedLength());
        logJson.addProperty("Resp. Len. Diff.",log.getLengthDifference());
        json.add(logJson);
      }
    }
    return json.toString();
  }

  public static String exportLogEntriesToCsv (ArrayList<LogEntry> logEntries, boolean exportHttp) {
    StringBuilder csv = new StringBuilder();
    if(exportHttp) {
      String csvHeader =
          "#"+","+
          "Method"+","+
          "URL"+","+
          "Orig. Status"+","+
          "Status"+","+
          "Orig. Resp. Len."+","+
          "Resp. Len."+","+
          "Resp. Len. Diff."+","+
          "Orig. Request"+","+
          "Orig. Response"+","+
          "Request"+","+
          "Response"+"\n";
      csv.append(csvHeader);
      for (LogEntry log : logEntries) {
        csv.append(log.getRequestResponseId());
        csv.append(",");
        csv.append(Utils.sanitizeForCsv(log.getModifiedMethod()));
        csv.append(",");
        csv.append(Utils.sanitizeForCsv(log.getModifiedURL().toString()));
        csv.append(",");
        csv.append(log.getOriginalResponseStatus());
        csv.append(",");
        csv.append(log.getModifiedResponseStatus());
        csv.append(",");
        csv.append(log.getOriginalLength());
        csv.append(",");
        csv.append(log.getModifiedLength());
        csv.append(",");
        csv.append(log.getLengthDifference());
        csv.append(",");
        csv.append(Utils.sanitizeForCsv(new String(log.getOriginalRequestResponse().getRequest())));
        csv.append(",");
        csv.append(Utils.sanitizeForCsv(new String(log.getOriginalRequestResponse().getResponse())));
        csv.append(",");
        csv.append(Utils.sanitizeForCsv(new String(log.getModifiedRequestResponse().getRequest())));
        csv.append(",");
        csv.append(Utils.sanitizeForCsv(new String(log.getModifiedRequestResponse().getResponse())));
        csv.append("\n");
      }
    } else {
      String csvHeader = "#"+","+
          "Method"+","+
          "URL"+","+
          "Orig. Status"+","+
          "Status"+","+
          "Orig. Resp. Len."+","+
          "Resp. Len."+","+
          "Resp. Len. Diff."+"\n";
      csv.append(csvHeader);
      for (LogEntry log : logEntries) {
        csv.append(log.getRequestResponseId());
        csv.append(",");
        csv.append(Utils.sanitizeForCsv(log.getModifiedMethod()));
        csv.append(",");
        csv.append(Utils.sanitizeForCsv(log.getModifiedURL().toString()));
        csv.append(",");
        csv.append(log.getOriginalResponseStatus());
        csv.append(",");
        csv.append(log.getModifiedResponseStatus());
        csv.append(",");
        csv.append(log.getOriginalLength());
        csv.append(",");
        csv.append(log.getModifiedLength());
        csv.append(",");
        csv.append(log.getLengthDifference());
        csv.append("\n");
      }
    }
    return csv.toString();
  }

  private static String sanitizeForCsv(String input) {
    return input.replaceAll("\n", "\\n").replaceAll(",", "\\,");
  }

  public static IHttpRequestResponse cloneIHttpRequestResponse(
      IHttpRequestResponse originalRequestResponse) {
    return new IHttpRequestResponse() {
      byte[] request = originalRequestResponse.getRequest();
      byte[] response = originalRequestResponse.getResponse();
      String comment = originalRequestResponse.getComment();
      String highlight = originalRequestResponse.getHighlight();
      IHttpService httpService = originalRequestResponse.getHttpService();

      @Override
      public byte[] getRequest() {
        return request;
      }

      @Override
      public void setRequest(byte[] message) {
        this.request = message;
      }

      @Override
      public byte[] getResponse() {
        return response;
      }

      @Override
      public void setResponse(byte[] message) {
        this.response = message;
      }

      @Override
      public String getComment() {
        return comment;
      }

      @Override
      public void setComment(String comment) {
        this.comment = comment;
      }

      @Override
      public String getHighlight() {
        return highlight;
      }

      @Override
      public void setHighlight(String color) {
        this.highlight = color;
      }

      @Override
      public IHttpService getHttpService() {
        return httpService;
      }

      @Override
      public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;
      }
    };
  }

  public static String getStringAfterSubstring (String input, String substring) {
    return(input.substring(input.lastIndexOf(substring) + substring.length()));
  }

  public static byte[] byteArrayRegexReplaceFirst(byte[] input, String regex, String replacement) {
    try {
      // I need to specify ASCII here because it's the easiest way for me to ensure the byte[] and
      // resulting string are the same length.
      String inputString = new String(input, "US-ASCII");
      Pattern pattern = Pattern.compile(regex);
      Matcher matcher = pattern.matcher(inputString);
      // I'll be appending a lot of it's just easier to use a list here
      ArrayList<Byte> output = new ArrayList<>();
      // the index of the start of the last match
      int currentIndex = 0;
      // Check all occurrences
      if (matcher.find()) {
        int start = matcher.start();
        // Add every item between start of the last match and the current match
        for (int i = currentIndex; i < start; i++) {
          output.add(input[i]);
        }
        // Add every character in the replacement
        for (int i = 0; i < replacement.length(); i++) {
          output.add((byte)replacement.charAt(i));
        }
        // Skip over the body of the match
        currentIndex = matcher.end();
      } else {
        //
        return input;
      }
      // Add everything after the last match
      for (int i = currentIndex; i < input.length; i++) {
        output.add(input[i]);
      }
      return byteArrayListToByteArray(output);
    } catch (UnsupportedEncodingException e) {
      return input;
    }

  }

  public static byte[] byteArrayRegexReplaceAll(byte[] input, String regex, String replacement) {
    try {
      // I need to specify ASCII here becasue it's the easiest way for me to ensure the byte[] and
      // resulting string are the same length.
      String inputString = new String(input, "US-ASCII");
      Pattern pattern = Pattern.compile(regex);
      Matcher matcher = pattern.matcher(inputString);
      // I'll be appending a lot of it's just easier to use a list here
      ArrayList<Byte> output = new ArrayList<>();

      //BurpExtender.getCallbacks().printOutput("Input Length is: ");
      //BurpExtender.getCallbacks().printOutput(Integer.toString(input.length));
      //BurpExtender.getCallbacks().printOutput("Input String Length is: ");
      //BurpExtender.getCallbacks().printOutput(Integer.toString(inputString.length()));

      // the index of the start of the last match
      int currentIndex = 0;
      // Check all occurrences
      while (matcher.find()) {
        int start = matcher.start();
        // Add every item between start of the last match and the current match
        for (int i = currentIndex; i < start; i++) {
          output.add(input[i]);
        }
        // Add every character in the replacement
        for (int i = 0; i < replacement.length(); i++) {
          output.add((byte)replacement.charAt(i));
        }
        // Skip over the body of the match
        currentIndex = matcher.end();
      }
      // Add everything after the last match
      for (int i = currentIndex; i < input.length; i++) {
        output.add(input[i]);
      }
      return byteArrayListToByteArray(output);
    } catch (UnsupportedEncodingException e) {
      return input;
    }
  }

  public static byte[] byteArrayListToByteArray(ArrayList<Byte> input) {
    byte[] output = new byte[input.size()];
    for (int i = 0; i < input.size(); i++) {
      output[i] = input.get(i);
    }
    return output;
  }

  //This method isn't efficient, i should refactor
  public static String getMultipartBoundary(byte[] request) {
    IExtensionHelpers helpers = BurpExtender.getHelpers();
    IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
    List<String> headers = analyzedRequest.getHeaders();
    return headers.stream()
        .filter((h) -> h.startsWith("Content-Type: multipart/form-data;"))
        .findFirst()
        .map((h) -> getStringAfterSubstring(h, "Content-Type: multipart/form-data;"))
        .map((h) -> getStringAfterSubstring(h, "boundary="))
        .map((h) -> "--"+h)
        .orElse(null);
  }

  public static Color getBurpOrange() {
    return new Color(0xff6633);
  }

  // This method is a mess.
  public static ArrayList<IParameter> getMultipartParameters(byte[] request)  {
    IExtensionHelpers helpers = BurpExtender.getHelpers();
    IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
    ArrayList<IParameter> parameters = new ArrayList<>();
    String boundary = getMultipartBoundary(request);
    String requestBodyString = new String(Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length));
    int index = requestBodyString.indexOf(boundary);
    while (index >= 0) {
      //BurpExtender.getCallbacks().printOutput(Integer.toString(index));
      int nextNewLineIndex = requestBodyString.indexOf('\n', index);
      index = requestBodyString.indexOf(boundary, index+1);
    }
    return parameters;
  }

  // It seems that IParameter types are incorrectly stated by the Burp Suite API
  // so I need to check
  public static boolean isRequestMultipartForm(byte[] request) {
    IExtensionHelpers helpers = BurpExtender.getHelpers();
    IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
    List<String> headers = analyzedRequest.getHeaders();
    return headers.stream().anyMatch((h) -> h.startsWith("Content-Type: multipart/form-data;"));
  }

  public static void highlightParentTab(JTabbedPane parentTabbedPane, Component childComponent) {
    if (parentTabbedPane != null) {
      for (int i = 0; i < parentTabbedPane.getTabCount(); i++) {
        if (parentTabbedPane.getComponentAt(i).equals(childComponent)) {
          parentTabbedPane.setBackgroundAt(i, getBurpOrange());
          Timer timer = new Timer(3000, e -> {
            for (int j = 0; j < parentTabbedPane.getTabCount(); j++) {
              if (parentTabbedPane.getComponentAt(j).equals(childComponent)) {
                parentTabbedPane.setBackgroundAt(j, Color.BLACK);
                break;
              }
            }
          });
          timer.setRepeats(false);
          timer.start();
          break;
        }
      }
    }
  }
}
