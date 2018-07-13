package burp.Conditions;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

public class ConditionTableModel extends AbstractTableModel {

  private String[] columnNames = {
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

  public void addCondition(Condition newCondition) {
    conditions.add(newCondition);
  }

  public void updateCondition(int replacementIndex, Condition newCondition) {
    if (replacementIndex == 0) {
      newCondition.setBooleanOperator("");
    }
    conditions.set(replacementIndex, newCondition);
  }

  public ArrayList<Condition> getConditions() {
    return conditions;
  }

  public Condition getCondition(int conditionIndex) {
    return conditions.get(conditionIndex);
  }

  public void deleteCondition(int replacementIndex) {
    if (replacementIndex != 0) {
      conditions.remove(replacementIndex);
    }
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
