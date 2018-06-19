package burp.Logs;

import burp.AutoRepeater.LogTable;
import javax.swing.*;
import java.awt.event.ActionEvent;

/**
 * Largely taken from Logger++
 */
public class LogEntryMenu extends JPopupMenu {

  public LogEntryMenu(final LogManager logManager, final LogTable logTable, final int row, final int col) {
    final LogEntry entry = logManager.getLogTableModel().getLogEntry(row);
    final String columnName = logManager.getLogTableModel().getColumnName(col);
    final String columnValue = logManager.getLogTableModel().getValueAt(row, col).toString();
    //this.add(new JPopupMenu.Separator());

    JMenuItem useAsFilter = new JMenuItem(
        new AbstractAction("Clear Logs") {
          @Override
          public void actionPerformed(ActionEvent actionEvent) {
            logManager.getLogTableModel().clearLogs();
            logTable.revalidate();
          }
        });
    this.add(useAsFilter);
  }
}


