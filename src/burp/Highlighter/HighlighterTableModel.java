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

  public HighlighterTableModel() {
    super();
    backgroundColor = Highlighter.COLORS[0];
    selectedBackgroundColor = Highlighter.SELECTED_COLORS[0];
    setColorName(Highlighter.COLOR_NAMES[0]);
  }

  //TODO: These are both bad. Why am i not just setting the value when the name is set to reduce the lookups.
  public Color getColor() {
    return backgroundColor;
  }

  public Color getSelectedColor() {
    return selectedBackgroundColor;
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
    for(int i = 0; i < Highlighter.COLOR_NAMES.length; i++) {
      if (Highlighter.COLOR_NAMES[i].equals(colorName)) {
        this.colorName = colorName;
        backgroundColor = Highlighter.COLORS[i];
        selectedBackgroundColor = Highlighter.SELECTED_COLORS[i];
      }
    }
    this.colorName = Highlighter.COLOR_NAMES[0];
    backgroundColor = Highlighter.COLORS[0];
    selectedBackgroundColor = Highlighter.SELECTED_COLORS[0];
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
