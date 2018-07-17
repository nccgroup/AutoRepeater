package burp.Filter;

import burp.Conditions.Condition;
import burp.IHttpRequestResponse;
import burp.Logs.LogEntry;
import java.util.ArrayList;
import javax.swing.table.AbstractTableModel;

public class FilterTableModel extends AbstractTableModel {
  private ArrayList<Filter> filters;

  private final static String[] columnNames = {
      "Enabled",
      "Boolean Operator",
      "Original Or Modified",
      "Match Type",
      "Match Relationship",
      "Match Condition"
  };


  // Setting default filters
  public FilterTableModel() {
    filters = new ArrayList<>();
  }

  public void addFilter(Filter filter) {
    filters.add(filter);
  }

  public void updateFilter(int replacementIndex, Filter filter) {
    if (replacementIndex == 0) {
      filter.setBooleanOperator("");
    }
    filters.set(replacementIndex, filter);
  }

  public boolean checkFilters(LogEntry logEntry) {
    boolean meetsFilters = false;
    if (getfilters().size() == 0) {
      meetsFilters = true;
    } else {
      if (getfilters()
          .stream()
          .filter(Filter::isEnabled)
          .filter(f -> f.getBooleanOperator().equals("Or"))
          .anyMatch(f -> f.checkCondition(logEntry))) {
        meetsFilters = true;
      }
      if (getfilters()
          .stream()
          .filter(Filter::isEnabled)
          .filter(f -> f.getBooleanOperator().equals("And") || f.getBooleanOperator().equals(""))
          .allMatch(f -> f.checkCondition(logEntry))) {
        meetsFilters = true;
      }
    }
    return meetsFilters;
  }

  public ArrayList<Filter> getfilters() {
    return filters;
  }

  public Filter getFilter(int filterIndex) {
    return filters.get(filterIndex);
  }

  public void deleteFilter(int index) {
    if (index != 0) {
      filters.remove(index);
    }
  }

  public void clearFilters() {
    filters.clear();
  }

  @Override
  public int getColumnCount() {
    return columnNames.length;
  }

  @Override
  public int getRowCount() {
    return filters.size();
  }

  @Override
  public String getColumnName(int col) {
    return columnNames[col];
  }

  @Override
  public Object getValueAt(int row, int col) {
    Filter filter = filters.get(row);
    switch (col) {
      case 0:
        return filter.isEnabled();
      case 1:
        return filter.getBooleanOperator();
      case 2:
        return filter.getOriginalOrModified();
      case 3:
        return filter.getMatchType();
      case 4:
        return filter.getMatchRelationship();
      case 5:
        return filter.getMatchCondition();
      default:
        throw new IllegalStateException("getValueAt not defined for "+Integer.toString(col));
    }
  }

  @Override
  public Class getColumnClass(int column) {
    return (getValueAt(0, column).getClass());
  }

  @Override
  public boolean isCellEditable(int row, int column) {
    return (getColumnName(column).equals("Enabled") && row != 0);
  }

  @Override
  public void setValueAt(Object value, int row, int col) {
    Filter filter = filters.get(row);
    switch (col) {
      case 0:
        filter.setEnabled((Boolean) value);
        break;
      case 1:
        filter.setBooleanOperator((String) value);
        break;
      case 2:
        filter.setOriginalOrModified((String) value);
        break;
      case 3:
        filter.setMatchType((String) value);
        break;
      case 4:
        filter.setMatchRelationship((String) value);
        break;
      default:
        filter.setMatchCondition((String) value);
        break;
    }
    filters.set(row, filter);
  }
}
