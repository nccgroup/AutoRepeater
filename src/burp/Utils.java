package burp;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.util.ArrayList;
import javax.swing.*;
import java.awt.*;

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
        csv.append(log.getModifiedMethod());
        csv.append(",");
        csv.append(log.getModifiedURL().toString());
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
        csv.append(log.getModifiedMethod());
        csv.append(",");
        csv.append(log.getModifiedURL().toString());
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

  public static void highlightParentTab(JTabbedPane parentTabbedPane, Component childComponent) {
    if (parentTabbedPane != null) {
      for (int i = 0; i < parentTabbedPane.getTabCount(); i++) {
        if (parentTabbedPane.getComponentAt(i).equals(childComponent)) {
          parentTabbedPane.setBackgroundAt(i, new Color(0xff6633));
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
