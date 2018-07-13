package burp.Filter;

//TODO: Notes for implementation.
// Each tab will has a list of filters.
// There will be three types of filters: whitelist, blacklist, and highlight
// Each filter will be a set of and/or checks based on conditions

import burp.Conditions.Condition;
import burp.Conditions.Conditions;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponsePersisted;
import burp.Logs.LogEntry;
import burp.Logs.LogTableModel;
import java.util.Comparator;
import javax.swing.RowFilter;
import javax.swing.table.TableRowSorter;

public class Filter {
  private Conditions whiteListConditions = new Conditions();
  private Conditions blackListConditions = new Conditions();
  //private RowFilter<LogTableModel, Integer> rowFilter = new RowFilter<LogTableModel, Integer>() {
  //  @Override
  //  public boolean include(Entry<? extends LogTableModel, ? extends Integer> entry) {
  //    LogTableModel logTableModel = entry.getModel();
  //    LogEntry logEntry = logTableModel.getLogEntry(entry.getIdentifier());
  //    int toolFlag = logEntry.getToolFlag();
  //    IHttpRequestResponsePersisted originalRequestResponse = logEntry.getOriginalRequestResponse();
  //    //return (whiteListConditions.checkConditions(toolFlag, originalRequestResponse)
  //    //    && !blackListConditions.checkConditions(toolFlag, originalRequestResponse));
  //    System.out.println(whiteListConditions.checkConditions(toolFlag, originalRequestResponse));
  //    return whiteListConditions.checkConditions(toolFlag, originalRequestResponse);
  //  }
  //};

  public boolean check(int toolFlag, IHttpRequestResponse originalRequestResponse) {
    System.out.println(whiteListConditions.getConditionTableModel().getConditions().size());
    return whiteListConditions.checkConditions(toolFlag, originalRequestResponse);
  }

  public void addWhiteListCondition(Condition c) {
    whiteListConditions.getConditionTableModel().addCondition(c);
  }

  //public RowFilter<LogTableModel, Integer> getRowFilter() {
  //  return rowFilter;
  //}
}
