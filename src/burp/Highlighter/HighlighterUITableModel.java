package burp.Highlighter;

import java.util.ArrayList;
import java.util.stream.Collectors;
import javax.swing.table.AbstractTableModel;

public class HighlighterUITableModel extends AbstractTableModel {
  private ArrayList<HighlighterTableModel> tableModels;

  private static final String[] columnNames = {"Enabled", "Color", "Comment"};

  public HighlighterUITableModel() {
    tableModels = new ArrayList<>();
  }

  public HighlighterUITableModel(HighlighterUITableModel highlighterUITableModel) {
    this();
    tableModels.addAll(highlighterUITableModel.getTableModels());
  }

  public ArrayList<HighlighterTableModel> getTableModels() { return tableModels; }

  public void add(HighlighterTableModel tableModel) {
    tableModels.add(tableModel);
    fireTableDataChanged();
  }

  public void update(int index, HighlighterTableModel tableModel) {
    tableModels.set(index, tableModel);
    fireTableDataChanged();
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
    fireTableCellUpdated(row, col);
  }

  @Override
  public Class getColumnClass(int column) {
    switch (column) {
      case 0:
        return Boolean.class;
      case 1:
        return String.class;
      case 2:
        return String.class;
      default:
        throw new IllegalStateException("getColumnClass not defined for "+Integer.toString(column));
    }
  }

  @Override
  public Object getValueAt(int row, int col) {
    HighlighterTableModel tableModel = tableModels.get(row);
    switch (col) {
      case 0:
        return tableModel.isEnabled();
      case 1:
        return tableModel.getColorName();
      case 2:
        return tableModel.getComment();
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
