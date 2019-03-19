package burp.Utils;

import burp.Utils.diff_match_patch;
import java.util.LinkedList;

public class HttpComparer {

  public static String diffText(String original, String modified) {
    if (original.length() > 10000 || modified.length() > 10000) {
      return "Input too large, cannot generate diff.";
    } else {
      diff_match_patch differ = new diff_match_patch();
      LinkedList<diff_match_patch.Diff> diff;
      diff = differ.diff_main(original, modified, true);
      differ.diff_cleanupSemantic(diff);
      return diffToHtml(diff);
    }
  }

  public static String diffLines(String original, String modified) {
    if (original.length() > 20000 || modified.length() > 20000) {
      return "Input too large, cannot generate diff.";
    } else {
      diff_match_patch differ = new diff_match_patch();
      diff_match_patch.LinesToCharsResult linesTochars = differ
          .diff_linesToChars(original, modified);
      LinkedList<diff_match_patch.Diff> diff = differ
          .diff_main(linesTochars.chars1, linesTochars.chars2, false);
      differ.diff_charsToLines(diff, linesTochars.lineArray);
      //differ.diff_cleanupSemantic(diff);
      return diffToHtml(diff);
    }
  }

  private static String diffToHtml(LinkedList<diff_match_patch.Diff> diff) {
    StringBuilder html = new StringBuilder();
    for (diff_match_patch.Diff aDiff : diff) {
      String text = aDiff.text
          .replace("&", "&amp;")
          .replace("<", "&lt;")
          .replace(">", "&gt;")
          .replace("\n", "<br>");
      switch (aDiff.operation) {
        case INSERT:
          html.append("<span style=\"background:#e6ffe6;\">").append(text).append("</span>");
          break;
        case DELETE:
          html.append("<span style=\"background:#ffe6e6;\">").append(text).append("</span>");
          break;
        case EQUAL:
          html.append("<span>").append(text).append("</span>");
          break;
      }
    }
    return html.toString();
  }

}
