package burp.Highlighter;

import burp.Filter.Filter;
import java.awt.Color;

public class Highlighter extends Filter {
  private int color;

  final static Color[] COLORS = {
    Color.WHITE,
    Color.RED,
    Color.ORANGE,
    Color.YELLOW,
    Color.GREEN,
    Color.CYAN,
    Color.PINK,
    Color.MAGENTA,
    Color.GRAY,
    Color.BLACK
  };

  public Highlighter(
      int color,
      String booleanOperator,
      String originalOrModified,
      String matchType,
      String matchRelationship,
      String matchCondition,
      boolean isEnabled ) {
    super(booleanOperator, originalOrModified, matchType, matchRelationship, matchCondition, isEnabled);
    setColor(color);
  }

  public Highlighter(
      int color,
      String booleanOperator,
      String originalOrModified,
      String matchType,
      String matchRelationship,
      String matchCondition) {
    this(color, booleanOperator, originalOrModified, matchType, matchRelationship, matchCondition, true);
  }

  public Color getColor() { return COLORS[color]; }
  public int getColorIndex() { return color; }

  public void setColor(int i) {
    if (i < 0 || i >= COLORS.length)  {
      color = 0;
    } else {
      color = i;
    }
  }

}
