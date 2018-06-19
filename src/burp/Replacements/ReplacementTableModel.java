package burp.Replacements;

import burp.Replacements.Replacement;
import java.util.stream.Collectors;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

public class ReplacementTableModel extends AbstractTableModel {

  private String[] columnNames = {
      "Enabled",
      "Type",
      "Match",
      "Replace",
      "Which",
      "Comment",
      "Regex Match",
  };

  private ArrayList<Replacement> replacements;

  public ReplacementTableModel() {
    replacements = new ArrayList<>();
  }

  public void addReplacement(Replacement newReplacement) {
    replacements.add(newReplacement);
  }

  public void updateReplacement(int replacementIndex, Replacement newReplacement) {
    replacements.set(replacementIndex, newReplacement);
  }

  public Replacement getReplacement(int replacementIndex) {
    return replacements.get(replacementIndex);
  }

  public ArrayList<Replacement> getReplacements() {
    return replacements.stream()
        .filter(Replacement::isEnabled)
        .collect(Collectors.toCollection(ArrayList::new));
  }

  public void deleteReplacement(int replacementIndex) {
    replacements.remove(replacementIndex);
  }

  @Override
  public int getColumnCount() {
    return columnNames.length;
  }

  @Override
  public int getRowCount() {
    return replacements.size();
  }

  @Override
  public String getColumnName(int col) {
    return columnNames[col];
  }

  @Override
  public Object getValueAt(int row, int col) {
    Replacement tempReplacement = replacements.get(row);
    switch (col) {
      case 0:
        return tempReplacement.isEnabled();
      case 1:
        return tempReplacement.getType();
      case 2:
        return tempReplacement.getMatch();
      case 3:
        return tempReplacement.getReplace();
      case 4:
        return tempReplacement.getWhich();
      case 5:
        return tempReplacement.getComment();
      default:
        return tempReplacement.isRegexMatch();
    }
  }

  @Override
  public Class getColumnClass(int column) {
    return (getValueAt(0, column).getClass());
  }

  @Override
  public boolean isCellEditable(int row, int column) {
    return (getColumnName(column).equals("Enabled"));
  }

  @Override
  public void setValueAt(Object value, int row, int col) {
    Replacement tempReplacement = replacements.get(row);
    switch (col) {
      case 0:
        tempReplacement.setEnabled((Boolean) value);
        break;
      case 1:
        tempReplacement.setType((String) value);
        break;
      case 2:
        tempReplacement.setMatch((String) value);
        break;
      case 3:
        tempReplacement.setReplace((String) value);
        break;
      case 4:
        tempReplacement.setWhich((String) value);
        break;
      case 5:
        tempReplacement.setComment((String) value);
        break;
      default:
        tempReplacement.setRegexMatch((Boolean) value);
        break;
    }
    replacements.set(row, tempReplacement);
  }
}
