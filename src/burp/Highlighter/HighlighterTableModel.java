package burp.Highlighter;

    import burp.Filter.FilterTableModel;
    import java.awt.Color;
    import java.util.ArrayList;
    import java.util.stream.Collectors;

public class HighlighterTableModel extends FilterTableModel{
  private String colorName;
  private boolean isEnabled;

  public HighlighterTableModel() {
    super();
    setColorName(Highlighter.COLOR_NAMES[0]);
  }

  public Color getColor() {
    for (int i = 0 ; i < Highlighter.COLOR_NAMES.length; i++) {
      if (Highlighter.COLOR_NAMES[i].equals(colorName)) {
        return Highlighter.COLORS[i];
      }
    }
    return Highlighter.COLORS[0];
  }

  public Color getSelectedColor() {
    for (int i = 0 ; i < Highlighter.COLOR_NAMES.length; i++) {
      if (Highlighter.COLOR_NAMES[i].equals(colorName)) {
        return Highlighter.SELECTED_COLORS[i];
      }
    }
    return Highlighter.SELECTED_COLORS[0];
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
  }

  public String getColorName() { return colorName; }

  @Override
  public void delete(int index) {
    getConditions().remove(index);
  }

  public void setColorName(String colorName) {
    for(String color : Highlighter.COLOR_NAMES) {
      if (color.equals(colorName)) {
        this.colorName = colorName;
        return;
      }
    }
    this.colorName = Highlighter.COLOR_NAMES[0];
  }

  public Highlighter get(int index) { return (Highlighter)super.get(index); }

  public boolean isEnabled() {
    return isEnabled;
  }

  public void setEnabled(boolean enabled) {
    isEnabled = enabled;
  }

  @Override
  public boolean isCellEditable(int row, int column) {
    return (getColumnName(column).equals("Enabled"));
  }
}
