package burp.Highlighter;

import burp.Filter.Filter;
import java.awt.Color;

public class Highlighter extends Filter {
  public final static Color[] COLORS = {
      new Color(0xFFFFFF),
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

  public final static Color[] SELECTED_COLORS = {
      new Color(0xFFC498),
      new Color(0xDF4444),
      new Color(0xDFa844),
      new Color(0xDFDF44),
      new Color(0x44DF44),
      new Color(0x44DFDF),
      new Color(0x4444DF),
      new Color(0xDFA8A8),
      new Color(0xDF44DF),
      new Color(0x949494),
  };

  public final static String[] COLOR_NAMES = {
      "WHITE",
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


  public static Color getColorFromColorName(String colorName) {
    for(int i = 0; i < Highlighter.COLOR_NAMES.length; i++) {
      if (Highlighter.COLOR_NAMES[i].equals(colorName)) {
        return Highlighter.COLORS[i];
      }
    }
    return Highlighter.COLORS[0];
  }

  public static Color getSelectedColorFromColorName(String colorName) {
    for(int i = 0; i < Highlighter.COLOR_NAMES.length; i++) {
      if (Highlighter.COLOR_NAMES[i].equals(colorName)) {
        return Highlighter.SELECTED_COLORS[i];
      }
    }
    return Highlighter.SELECTED_COLORS[0];
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

  public Highlighter(Highlighter highlighter) {
    this(highlighter.getBooleanOperator(),
        highlighter.getOriginalOrModified(),
        highlighter.getMatchType(),
        highlighter.getMatchRelationship(),
        highlighter.getMatchCondition(),
        highlighter.isEnabled());
    if (this.getBooleanOperator().equals("")) {
      setBooleanOperator("And");
    }
  }
}
