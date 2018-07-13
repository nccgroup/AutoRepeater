package burp.Logs;

import burp.Filter.Filter;
import burp.Logs.LogEntry;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

public class LogTableModel extends AbstractTableModel {

  private final ArrayList<LogEntry> log = new ArrayList<>();
  private ArrayList<LogEntry> filteredLogs = new ArrayList<>();
  private Filter filter;

  public LogTableModel(Filter filter) {
    this.filter = filter;
  }

  public void addLogEntry(LogEntry newLogEntry) {
    log.add(newLogEntry);
    if(filter.check(newLogEntry.getToolFlag(), newLogEntry.getOriginalRequestResponse())) {
      filteredLogs.add(newLogEntry);
    }
  }

  public void filterLogs() {
    new Thread(() -> {
      filteredLogs = new ArrayList<>();
      for (LogEntry logEntry : log) {
        if(filter.check(logEntry.getToolFlag(), logEntry.getOriginalRequestResponse())) {
          filteredLogs.add(logEntry);
          System.out.println("Adding row "+logEntry.getRequestResponseId());
          fireTableDataChanged();
        }
      }
    }).start();
  }

  public void setFilter(Filter filter) {
    this.filter = filter;
  }

  public void clearLogs() {
    log.clear();
    filteredLogs.clear();
  }

  public LogEntry getLogEntry(int row) {
    //return log.get(row);
    return filteredLogs.get(row);
  }

  public ArrayList<LogEntry> getLog() {
      //return log;
      return log;
  }

  public ArrayList<LogEntry> getFilteredLogs() {
    //return log;
    return filteredLogs;
  }

  public int getLogCount() {
    return log.size();
  }

  @Override
  public int getRowCount() {
    //return log.size();
    return filteredLogs.size();
  }

  @Override
  public int getColumnCount() {
    return 8;
  }

  @Override
  public String getColumnName(int columnIndex) {
    switch (columnIndex) {
      case 0:
        return "#";
      case 1:
        return "Method";
      case 2:
        return "URL";
      case 3:
        return "Orig. Status";
      case 4:
        return "Status";
      case 5:
        return "Orig. Resp. Len.";
      case 6:
        return "Resp. Len.";
      case 7:
        return "Resp. Len. Diff.";
      default:
        return "";
    }
  }

  @Override
  public Class<?> getColumnClass(int columnIndex) {
    switch (columnIndex) {
      case 0:
        return Integer.class;
      case 1:
        return String.class;
      case 2:
        return String.class;
      case 3:
        return Integer.class;
      case 4:
        return Integer.class;
      case 5:
        return Integer.class;
      case 6:
        return Integer.class;
      case 7:
        return Integer.class;
      default:
        return null;
    }
  }

  @Override
  public Object getValueAt(int rowIndex, int columnIndex) {
    //LogEntry logEntry = log.get(rowIndex);
    LogEntry logEntry = filteredLogs.get(rowIndex);

    // ID, Mod Method, Mod URL, Orig Status, Mod Status, Orig Size, Mod Size, Size Difference, Response Distance
    switch (columnIndex) {
      case 0:
        return logEntry.getRequestResponseId();
      case 1:
        return logEntry.getModifiedMethod();
      case 2:
        return logEntry.getModifiedURL().toString();
      case 3:
        return logEntry.getOriginalResponseStatus();
      case 4:
        return logEntry.getModifiedResponseStatus();
      case 5:
        return logEntry.getOriginalLength();
      case 6:
        return logEntry.getModifiedLength();
      case 7:
        return logEntry.getLengthDifference();
      default:
        return "";
    }
  }
}
