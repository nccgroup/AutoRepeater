package burp.Utils;

import burp.AutoRepeater;
import burp.BurpExtender;
import burp.IExtensionStateListener;
import burp.Logs.LogEntry;
import burp.Logs.LogManager;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.ArrayList;

public class AutoRepeaterMenu implements Runnable, IExtensionStateListener {
  private final JRootPane rootPane;
  private static ArrayList<AutoRepeater> autoRepeaters;

  private static JMenu autoRepeaterJMenu;
  private static JMenuItem toggleSettingsVisibility;

  private static boolean showSettingsPanel;

  public static boolean sendRequestsToPassiveScanner;
  public static boolean addRequestsToSiteMap;

  public AutoRepeaterMenu(JRootPane rootPane) {
    this.rootPane = rootPane;
    autoRepeaters = BurpExtender.getAutoRepeaters();
    showSettingsPanel = true;
    BurpExtender.getCallbacks().registerExtensionStateListener(this);
  }

  /**
   * Action listener for setting visibility
   */
  class SettingVisibilityListener implements ActionListener {
    @Override
    public void actionPerformed(ActionEvent e) {
      // Toggling settings panel
      if (toggleSettingsVisibility.getText().equals("Hide Settings Panel")) {
        showSettingsPanel = false;
        toggleSettingsVisibility.setText("Show Settings Panel");
      } else {
        showSettingsPanel = true;
        toggleSettingsVisibility.setText("Hide Settings Panel");
      }
      // toggling every AutoRepeater tab
      for (AutoRepeater ar : autoRepeaters) {
        ar.toggleConfigurationPane(showSettingsPanel);
      }
    }
  }

  /**
   * Action listener for import settings menu
   */
  class ImportSettingListener implements ActionListener {

    @Override
    public void actionPerformed(ActionEvent e) {
      final JFileChooser importPathChooser = new JFileChooser();
      int replaceTabs = JOptionPane.showConfirmDialog(rootPane, "Would you like to replace the current tabs?", "Replace Tabs", JOptionPane.YES_NO_CANCEL_OPTION);
      if (replaceTabs == 2) {
        // cancel selected
        return;
      }
      int returnVal = importPathChooser.showOpenDialog(rootPane);
      if (returnVal != JFileChooser.APPROVE_OPTION) {
        BurpExtender.getCallbacks().printOutput("Cannot open a file dialog for importing settings.");
        return;
      }
      File file = importPathChooser.getSelectedFile();
      String fileData = Utils.readFile(file);
      if (fileData.equals("")) {
        // file empty
        return;
      }
      if (replaceTabs == 1) {
        // do not replace current tabs
        BurpExtender.initializeFromSave(fileData, false);
      } else if (replaceTabs == 0) {
        // replace current tabs
        BurpExtender.getCallbacks().printOutput("Removing Tabs");
        BurpExtender.initializeFromSave(fileData, true);
      }
    }
  }

  /**
   * Action listener for export settings menu.
   */
  class ExportSettingListener implements ActionListener {
    @Override
    public void actionPerformed(ActionEvent e) {
      Object[] options = {"Current Tab", "Every Tab", "Cancel"};
      int option = JOptionPane.showOptionDialog(rootPane, "Which tab would you like to export?", "Export Tabs",
          JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);
      if (option == 2) { return; }
      final JFileChooser exportPathChooser = new JFileChooser();
      int returnVal = exportPathChooser.showSaveDialog(rootPane);
      if (returnVal != JFileChooser.APPROVE_OPTION) {
        BurpExtender.getCallbacks().printOutput("Cannot open a file dialog for exporting settings.");
        return;
      }
      File file = exportPathChooser.getSelectedFile();
      try (PrintWriter out = new PrintWriter(file.getAbsolutePath())) {
        if (option == 0) {
          // export current tab
          out.println(BurpExtender.exportSave(BurpExtender.getSelectedAutoRepeater()));
        } else if (option == 1) {
          // export every tab
          out.println(BurpExtender.exportSave());
        }
      } catch (FileNotFoundException error) {
        error.printStackTrace();
      }
    }
  }

  /**
   * Action listener for export logs menu.
   */
  class ExportLogsListener implements ActionListener {

    @Override
    public void actionPerformed(ActionEvent e) {
      Object[] options = {"Export", "Cancel"};
      final String[] EXPORT_OPTIONS = {"CSV", "JSON"};
      final String[] EXPORT_WHICH_OPTIONS = {"All Tab Logs", "Selected Tab Logs"};
      final String[] EXPORT_VALUE_OPTIONS = {"Log Entry", "Log Entry + Full HTTP Request"};

      final JComboBox<String> exportTypeComboBox = new JComboBox<>(EXPORT_OPTIONS);
      final JComboBox<String> exportWhichComboBox = new JComboBox<>(EXPORT_WHICH_OPTIONS);
      final JComboBox<String> exportValueComboBox = new JComboBox<>(EXPORT_VALUE_OPTIONS);

      final JFileChooser exportLogsPathChooser = new JFileChooser();

      JPanel exportLogsPanel = new JPanel();
      exportLogsPanel.setLayout(new BoxLayout(exportLogsPanel, BoxLayout.PAGE_AXIS));
      exportLogsPanel.add(exportWhichComboBox);
      exportLogsPanel.add(exportValueComboBox);
      exportLogsPanel.add(exportTypeComboBox);
      JPanel buttonPanel = new JPanel();
      exportLogsPanel.add(buttonPanel);

      int option = JOptionPane.showOptionDialog(rootPane, exportLogsPanel,
          "Export Logs", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);
      if (option == 1) {
        return;
      }
      int returnVal = exportLogsPathChooser.showSaveDialog(rootPane);
      if (returnVal != JFileChooser.APPROVE_OPTION) {
        BurpExtender.getCallbacks().printOutput("Cannot open a file dialog for exporting logs.");
        return;
      }
      AutoRepeater autoRepeater = BurpExtender.getSelectedAutoRepeater();
      LogManager logManager = autoRepeater.getLogManager();
      File file = exportLogsPathChooser.getSelectedFile();
      ArrayList<LogEntry> logEntries = new ArrayList<>();
      // collect relevant entries
      if ((exportWhichComboBox.getSelectedItem()).equals("All Tab Logs")) {
        logEntries = autoRepeater.getLogTableModel().getLog();
      } else if ((exportWhichComboBox.getSelectedItem()).equals("Selected Tab Logs")) {
        int[] selectedRows = autoRepeater.getLogTable().getSelectedRows();
        for (int row : selectedRows) {
          logEntries.add(logManager.getLogEntry(autoRepeater.getLogTable().convertRowIndexToModel(row)));
        }
      }
      // determine if whole request should be exported or just the log contents
      boolean exportFullHttp = !((exportValueComboBox.getSelectedItem()).equals("Log Entry"));

      try (PrintWriter out = new PrintWriter(file.getAbsolutePath())) {
        if ((exportTypeComboBox.getSelectedItem()).equals("CSV")) {
          out.println(Utils.exportLogEntriesToCsv(logEntries, exportFullHttp));
        } else if ((exportTypeComboBox.getSelectedItem()).equals("JSON")) {
          out.println(Utils.exportLogEntriesToJson(logEntries, exportFullHttp));
        }
      } catch (FileNotFoundException error) {
        error.printStackTrace();
      }
    }
  }

  class DuplicateCurrentTabListener implements ActionListener {

    @Override
    public void actionPerformed(ActionEvent e) {
      JsonArray serializedTab = BurpExtender.exportSaveAsJson(BurpExtender.getSelectedAutoRepeater());
      for (JsonElement tabConfiguration : serializedTab) {
        BurpExtender.addNewTab(tabConfiguration.getAsJsonObject());
      }
    }
  }

  @Override
  public void extensionUnloaded() {
    // unregister menu
    JMenuBar burpMenuBar = rootPane.getJMenuBar();
    BurpExtender.getCallbacks().printOutput("Unregistering menu");
    burpMenuBar.remove(autoRepeaterJMenu);
    burpMenuBar.repaint();
  }

  @Override
  public void run() {
    JMenuBar burpJMenuBar = rootPane.getJMenuBar();
    autoRepeaterJMenu = new JMenu("AutoRepeater");
    // initialize menu items and add action listeners
    JMenuItem duplicateCurrentTab = new JMenuItem("Duplicate Selected Tab");
    duplicateCurrentTab.addActionListener(new DuplicateCurrentTabListener());

    toggleSettingsVisibility = new JMenuItem("Hide Settings Panel");
    toggleSettingsVisibility.addActionListener(new SettingVisibilityListener());
    JCheckBoxMenuItem toggleSendRequestsToPassiveScanner = new JCheckBoxMenuItem("Send Requests To Passive Scanner");
    toggleSendRequestsToPassiveScanner.addActionListener(l ->
        sendRequestsToPassiveScanner = toggleSendRequestsToPassiveScanner.getState());

    JCheckBoxMenuItem toggleAddRequestsToSiteMap = new JCheckBoxMenuItem("Add Requests To Site Map");
    toggleAddRequestsToSiteMap.addActionListener(l ->
        addRequestsToSiteMap = toggleAddRequestsToSiteMap.getState());

    JMenuItem showImportMenu = new JMenuItem("Import Settings");
    showImportMenu.addActionListener(new ImportSettingListener());

    JMenuItem showExportMenu = new JMenuItem("Export Settings");
    showExportMenu.addActionListener(new ExportSettingListener());

    JMenuItem showExportLogsMenu = new JMenuItem("Export Logs");
    showExportLogsMenu.addActionListener(new ExportLogsListener());
    // add menu items to the menu
    autoRepeaterJMenu.add(duplicateCurrentTab);
    autoRepeaterJMenu.add(toggleSettingsVisibility);
    autoRepeaterJMenu.addSeparator();
    autoRepeaterJMenu.add(toggleAddRequestsToSiteMap);
    autoRepeaterJMenu.add(toggleSendRequestsToPassiveScanner);
    autoRepeaterJMenu.addSeparator();
    autoRepeaterJMenu.add(showImportMenu);
    autoRepeaterJMenu.add(showExportMenu);
    autoRepeaterJMenu.add(showExportLogsMenu);
    // add menu to menu bar
    burpJMenuBar.add(autoRepeaterJMenu, burpJMenuBar.getMenuCount() - 2);
  }
}
