package burp.Highlighter;

import java.util.ArrayList;
import javax.swing.table.AbstractTableModel;

public class HighlighterUITableModel extends AbstractTableModel {
  private ArrayList<HighlighterTableModel> tableModels;

  private static final String[] columnNames = {"Enabled", "Color"};

  public HighlighterUITableModel() {
    tableModels = new ArrayList<>();
  }

  public ArrayList<HighlighterTableModel> getTableModels() { return tableModels; }

  public void add(HighlighterTableModel tableModel) {
    tableModels.add(tableModel);
  }

  public void update(int index, HighlighterTableModel tableModel) {
    tableModels.set(index, tableModel);
  }

  public HighlighterTableModel get(int index) {
    return tableModels.get(index);
  }

  public void remove(int index) {
    tableModels.remove(index);
  }

  @Override
  public int getRowCount() {
    return tableModels.size();
  }

  @Override
  public int getColumnCount() {
    return columnNames.length;
  }

  @Override
  public void setValueAt(Object value, int row, int col) {
    HighlighterTableModel tableModel = tableModels.get(row);
    switch (col) {
      case 0:
        tableModel.setEnabled((Boolean) value);
        break;
      default:
        break;
    }
    tableModels.set(row, tableModel);
  }

  @Override
  public Class getColumnClass(int column) {
    return (getValueAt(0, column).getClass());
  }

  @Override
  public Object getValueAt(int row, int col) {
    HighlighterTableModel tableModel = tableModels.get(row);
    switch (col) {
      case 0:
        return tableModel.isEnabled();
      case 1:
        return tableModel.getColorName();
      default:
        throw new IllegalStateException("getValueAt not defined for "+Integer.toString(col));
    }
  }

  @Override
  public boolean isCellEditable(int row, int column) {
    return (getColumnName(column).equals("Enabled"));
  }

  @Override
  public String getColumnName(int col) {
    return columnNames[col];
  }
}
