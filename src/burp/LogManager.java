package burp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.ListIterator;

public class LogManager {

  private LogTableModel logTableModel;
  private ArrayList<LogEntry> entriesWithoutResponses;
  //private IBurpExtenderCallbacks callbacks;
  private int matchCounter = 0;

  public LogManager(LogTableModel logTableModel) {
    this.logTableModel = logTableModel;
    //this.callbacks = callbacks;
    entriesWithoutResponses = new ArrayList<>();
  }

  public synchronized int getRowCount() {
    return logTableModel.getRowCount();
  }

  public synchronized LogTableModel getLogTableModel() {
    return logTableModel;
  }

  public synchronized LogEntry getLogEntry(int row) {
    return logTableModel.getLogEntry(row);
  }

  public synchronized void addEntry(LogEntry logEntry) {
    logTableModel.addLogEntry(logEntry);
    //entriesWithoutResponses.add(logEntry);
  }

  //Keeping this around incase i go to switch the trigger back to on request
  public synchronized void addEntryResponse(IHttpRequestResponse messageInfo) {
    int requestHashCode = Arrays.hashCode(messageInfo.getRequest());
    ListIterator<LogEntry> iter = entriesWithoutResponses.listIterator();

    System.out.println("LogEntriesWithoutResponses Length");
    System.out.println(entriesWithoutResponses.size());

    for (LogEntry lg : entriesWithoutResponses) {
      System.out.print("Entries Hash is: ");
      System.out.println(lg.getOriginalRequestHashCode());
    }
    System.out.print("Current hashcode: ");
    System.out.println(requestHashCode);

    System.out.print("matchCounter is: ");
    System.out.println(matchCounter);

    while (iter.hasNext()) {
      // If the current LogEntry's originalRequest matches the received request set them equal
      LogEntry currentLogEntry = iter.next();
      if (currentLogEntry.getOriginalRequestHashCode() == requestHashCode) {
        currentLogEntry.setOriginalRequestResponse(
            BurpExtender.getCallbacks().saveBuffersToTempFiles(messageInfo));
        iter.remove();
        matchCounter++;
        break;
      }
      if (currentLogEntry.getRequestSentTime() + 60000 < System.currentTimeMillis()) {
        System.out.println("TIME OUT");
        System.out.println(currentLogEntry.getRequestSentTime());
        System.out.println(System.currentTimeMillis());
        iter.remove();
      }
    }
    System.out.println();
  }

  public synchronized void fireTableRowsUpdated(int firstRow, int lastRow) {
    logTableModel.fireTableRowsInserted(firstRow, lastRow);
  }

}
