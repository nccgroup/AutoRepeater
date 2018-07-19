package burp.Highlighter;

import burp.Filter.FilterTableModel;
import java.util.ArrayList;
import java.util.stream.Collectors;

public class HighlighterTableModel extends FilterTableModel{
  private String color;
  private boolean isEnabled;

  public HighlighterTableModel() {
    super();
    setColor(Highlighter.COLOR_NAMES[0]);
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
    this.color = highlighterTableModel.getColor();
    this.isEnabled = highlighterTableModel.isEnabled();
  }

  public String getColor() { return color; }

  public void setColor(String color) {
    for(String colorName : Highlighter.COLOR_NAMES) {
      if (color.equals(colorName)) {
        this.color = color;
        return;
      }
    }
    this.color = Highlighter.COLOR_NAMES[0];
  }

  public Highlighter get(int index) { return (Highlighter)super.get(index); }

  public boolean isEnabled() {
    return isEnabled;
  }

  public void setEnabled(boolean enabled) {
    isEnabled = enabled;
  }
}
