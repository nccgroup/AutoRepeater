package burp.Highlighter;

import burp.Filter.Filter;
import burp.Filter.FilterTableModel;
import java.util.ArrayList;
import java.util.stream.Collectors;

public class HighlighterTableModel extends FilterTableModel{
  private final static String[] columnNames = {
      "Enabled",
      "Color",
      "Boolean Operator",
      "Original Or Modified",
      "Match Type",
      "Match Relationship",
      "Match Condition"
  };

  public ArrayList<Highlighter> getHighlighters() {
    return getConditions().stream()
        .map(x -> (Highlighter)x)
        .collect(Collectors.toCollection(ArrayList::new));
  }

  public Highlighter get(int index) { return (Highlighter)super.get(index); }

  @Override
  public String getColumnName(int col) {
    return columnNames[col];
  }

  @Override
  public Object getValueAt(int row, int col) {
    Highlighter highlighter = get(row);
    switch (col) {
      case 0:
        return highlighter.isEnabled();
      case 1:
        return highlighter.getColorIndex();
      case 2:
        return highlighter.getBooleanOperator();
      case 3:
        return highlighter.getOriginalOrModified();
      case 4:
        return highlighter.getMatchType();
      case 5:
        return highlighter.getMatchRelationship();
      case 6:
        return highlighter.getMatchCondition();
      default:
        throw new IllegalStateException("getValueAt not defined for "+Integer.toString(col));
    }
  }

  @Override
  public void setValueAt(Object value, int row, int col) {
    Highlighter highlighter = get(row);
    switch (col) {
      case 0:
        highlighter.setEnabled((Boolean) value);
        break;
      case 1:
        highlighter.setColor((int) value);
        break;
      case 2:
        highlighter.setBooleanOperator((String) value);
        break;
      case 3:
        highlighter.setOriginalOrModified((String) value);
        break;
      case 4:
        highlighter.setMatchType((String) value);
        break;
      case 5:
        highlighter.setMatchRelationship((String) value);
        break;
      default:
        highlighter.setMatchCondition((String) value);
        break;
    }
    update(row, highlighter);
  }
}
