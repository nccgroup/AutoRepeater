package burp.Utils;

import javax.swing.*;

public class DiffViewerPane extends JEditorPane {

  public DiffViewerPane(byte[] original, byte[] modified) {
    this.setEditable(false);
    this.setContentType("text/html");
  }

  public DiffViewerPane() {
    this.setEditable(false);
    this.setContentType("text/html");
  }


}
