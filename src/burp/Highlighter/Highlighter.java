package burp.Highlighter;

import burp.Filter.Filter;
import java.awt.Color;

public class Highlighter extends Filter {
  private int color;

  final static Color[] COLORS = {
      new Color(0xFB6063),
      new Color(0xFFC562),
      new Color(0xFDFF5F),
      new Color(0x60FE62),
      new Color(0x64FFFF),
      new Color(0x6262FF),
      new Color(0xFFC6CC),
      new Color(0xFE63FD) ,
      new Color(0xB3B5B2),
  };

  final static String[] COLOR_NAMES = {
      "RED",
      "ORANGE",
      "YELLOW",
      "GREEN",
      "CYAN",
      "PURPLE",
      "PINK",
      "MAGENTA",
      "GRAY"
  };

  public static Color getColorFromName(String colorName) {
    for (int i = 0; i < COLOR_NAMES.length; i++) {
      if (COLOR_NAMES[i].equals(colorName)) {
        return COLORS[i];
      }
    }
    return COLORS[0];
  }

  public Highlighter(
      String booleanOperator,
      String originalOrModified,
      String matchType,
      String matchRelationship,
      String matchCondition,
      boolean isEnabled) {
    super(booleanOperator, originalOrModified, matchType, matchRelationship, matchCondition, isEnabled);
  }

  public Highlighter(
      String booleanOperator,
      String originalOrModified,
      String matchType,
      String matchRelationship,
      String matchCondition) {
    this(booleanOperator, originalOrModified, matchType, matchRelationship, matchCondition, true);
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
