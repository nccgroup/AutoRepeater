package burp.Conditions;

import burp.IHttpRequestResponse;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

public class ConditionTableModel extends AbstractTableModel {

  private final static String[] columnNames = {
      "Enabled",
      "Boolean Operator",
      "Match Type",
      "Match Relationship",
      "Match Condition"
  };

  private ArrayList<Condition> conditions;

  // Setting default conditions
  public ConditionTableModel() {
    conditions = new ArrayList<>();
  }

  public void add(Condition condition) {
    conditions.add(condition);
  }

  public void update(int index, Condition condition) {
    if (index == 0) {
      condition.setBooleanOperator("");
    }
    conditions.set(index, condition);
  }

  public boolean check(int toolFlag, IHttpRequestResponse messageInfo) {
    boolean meetsConditions = false;
    if (getConditions().size() == 0) {
      meetsConditions = true;
    } else {
      if (getConditions()
          .stream()
          .filter(Condition::isEnabled)
          .filter(c -> c.getBooleanOperator().equals("Or"))
          .anyMatch(c -> c.checkCondition(toolFlag, messageInfo))) {
        meetsConditions = true;
      }
      if (getConditions()
          .stream()
          .filter(Condition::isEnabled)
          .filter(
              c -> c.getBooleanOperator().equals("And") || c.getBooleanOperator().equals(""))
          .allMatch(c -> c.checkCondition(toolFlag, messageInfo))) {
        meetsConditions = true;
      }
    }
    return meetsConditions;
  }

  public ArrayList<Condition> getConditions() {
    return conditions;
  }

  public Condition get(int conditionIndex) {
    return conditions.get(conditionIndex);
  }

  public void delete(int index) {
    if (index != 0) { conditions.remove(index); }
  }

  public void clear() {
    conditions.clear();
  }

  @Override
  public int getColumnCount() {
    return columnNames.length;
  }

  @Override
  public int getRowCount() {
    return conditions.size();
  }

  @Override
  public String getColumnName(int col) {
    return columnNames[col];
  }

  @Override
  public Object getValueAt(int row, int col) {
    Condition tempCondition = conditions.get(row);
    switch (col) {
      case 0:
        return tempCondition.isEnabled();
      case 1:
        return tempCondition.getBooleanOperator();
      case 2:
        return tempCondition.getMatchType();
      case 3:
        return tempCondition.getMatchRelationship();
      case 4:
        return tempCondition.getMatchCondition();
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
    Condition tempCondition = conditions.get(row);
    switch (col) {
      case 0:
        tempCondition.setEnabled((Boolean) value);
        break;
      case 1:
        tempCondition.setBooleanOperator((String) value);
        break;
      case 2:
        tempCondition.setMatchType((String) value);
        break;
      case 3:
        tempCondition.setMatchRelationship((String) value);
        break;
      default:
        tempCondition.setMatchCondition((String) value);
        break;
    }
    conditions.set(row, tempCondition);
  }
}
