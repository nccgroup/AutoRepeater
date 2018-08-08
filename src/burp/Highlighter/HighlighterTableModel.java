package burp.Highlighter;

import burp.Filter.FilterTableModel;
import java.awt.Color;
import java.util.ArrayList;
import java.util.stream.Collectors;

public class HighlighterTableModel extends FilterTableModel{
  private String colorName;
  private boolean isEnabled;
  private Color backgroundColor;
  private Color selectedBackgroundColor;
  private String comment;

  public HighlighterTableModel() {
    super();
    backgroundColor = Highlighter.COLORS[0];
    selectedBackgroundColor = Highlighter.SELECTED_COLORS[0];
    setColorName(Highlighter.COLOR_NAMES[0]);
  }

  public void setComment(String comment) {
    this.comment = comment;
    fireTableDataChanged();
  }

  public String getComment() {return this.comment;}

  public Color getColor() {
    return backgroundColor;
  }

  public Color getSelectedColor() {
    return selectedBackgroundColor;
  }

  public void add(Highlighter highlighter) {
    super.add(highlighter);
    // Clear out the boolean if it's the first entry
    if (getConditions().get(0).equals(highlighter)) {
      getConditions().get(0).setBooleanOperator("");
    }
    fireTableDataChanged();
  }

  @Override
  public void remove(int index) {
    getConditions().remove(index);
    // Clear out the boolean if it's the first entry
    getConditions().get(0).setBooleanOperator("");
    fireTableDataChanged();
  }

  public ArrayList<Highlighter> getHighlighters() {
    return getConditions().stream()
        .map(x -> (Highlighter)x)
        .collect(Collectors.toCollection(ArrayList::new));
  }

  public HighlighterTableModel (HighlighterTableModel highlighterTableModel) {
    super();
    for (Highlighter highlighter : highlighterTableModel.getHighlighters()) {
      add(highlighter);
    }
    this.colorName = highlighterTableModel.getColorName();
    this.isEnabled = highlighterTableModel.isEnabled();
    this.backgroundColor = highlighterTableModel.getColor();
    this.selectedBackgroundColor = highlighterTableModel.getSelectedColor();
    this.comment = highlighterTableModel.getComment();
  }

  public String getColorName() { return colorName; }

  public void setColorName(String colorName) {
    for(int i = 0; i < Highlighter.COLOR_NAMES.length; i++) {
      if (Highlighter.COLOR_NAMES[i].equals(colorName)) {
        this.colorName = colorName;
        this.backgroundColor = Highlighter.COLORS[i];
        this.selectedBackgroundColor = Highlighter.SELECTED_COLORS[i];
        fireTableDataChanged();
        return;
      }
    }
    // This should never actually happen
    this.colorName = Highlighter.COLOR_NAMES[0];
    this.backgroundColor = Highlighter.COLORS[0];
    this.selectedBackgroundColor = Highlighter.SELECTED_COLORS[0];
    fireTableDataChanged();
  }

  public Highlighter get(int index) { return (Highlighter)super.get(index); }

  public boolean isEnabled() {
    return isEnabled;
  }

  public void setEnabled(boolean enabled) {
    isEnabled = enabled;
    fireTableDataChanged();
  }

  @Override
  public boolean isCellEditable(int row, int column) {
    return (getColumnName(column).equals("Enabled"));
  }
}
