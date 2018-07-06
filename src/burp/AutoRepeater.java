package burp;

import burp.Conditions.Condition;
import burp.Conditions.Conditions;
import burp.Logs.LogEntry;
import burp.Logs.LogEntryMenu;
import burp.Logs.LogManager;
import burp.Logs.LogTableModel;
import burp.Replacements.Replacement;
import burp.Replacements.ReplacementTableModel;
import burp.Utils.DiffViewerPane;
import burp.Utils.HttpComparer;
import burp.Utils.Utils;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableModel;

public class AutoRepeater implements IMessageEditorController {

  // UI Component Dimensions
  public static final Dimension dialogDimension = new Dimension(400, 140);
  public static final Dimension comboBoxDimension = new Dimension(250, 20);
  public static final Dimension textFieldDimension = new Dimension(250, 25);
  public static final Dimension buttonDimension = new Dimension(75, 20);
  public static final Dimension buttonPanelDimension = new Dimension(75, 60) ;
  public static final Dimension tableDimension = new Dimension(200, 40);

  private IBurpExtenderCallbacks callbacks;
  private IExtensionHelpers helpers;
  private Gson gson;
  private JTabbedPane tabs;

  // Splitpane that holds top and bottom halves of the ui
  private JSplitPane mainSplitPane;

  // These hold the http request viewers at the bottom
  private JSplitPane originalRequestResponseSplitPane;
  private JSplitPane modifiedRequestResponseSplitPane;

  // this split pane holds the request list and configuration panes
  private JSplitPane userInterfaceSplitPane;

  private LogTable logTable;

  private DiffViewerPane requestComparer;
  private DiffViewerPane responseComparer;

  private DiffViewerPane requestLineComparer;
  private DiffViewerPane responseLineComparer;

  // request/response viewers
  private IMessageEditor originalRequestViewer;
  private IMessageEditor originalResponseViewer;
  private IMessageEditor modifiedRequestViewer;
  private IMessageEditor modifiedResponseViewer;

  // Panels for including request/response viewers + labels
  private JPanel originalRequestPanel;
  private JPanel modifiedRequestPanel;
  private JPanel originalResponsePanel;
  private JPanel modifiedResponsePanel;

  private JLabel originalRequestLabel;
  private JLabel modifiedRequestLabel;
  private JLabel originalResponseLabel;
  private JLabel modifiedResponseLabel;

  byte[] originalRequest;
  byte[] originalResponse;
  byte[] modifiedRequest;
  byte[] modifiedResponse;

  String requestDiff;
  String responseDiff;
  String requestLineDiff;
  String responseLineDiff;

  JScrollPane requestComparerScrollPane;
  JScrollPane responseComparerScollPane;

  JScrollPane requestLineComparerScrollPane;
  JScrollPane responseLineComparerScollPane;

  // List of log entries for LogTable
  private LogTableModel logTableModel;
  private LogManager logManager;

  // The current item selected in the log table
  private IHttpRequestResponsePersisted currentOriginalRequestResponse;
  private IHttpRequestResponsePersisted currentModifiedRequestResponse;

  // The tabbed pane that holds the configuration options
  private JPanel configurationPane;
  private JTabbedPane configurationTabbedPane;

  // The button that indicates weather Auto Repater is on or not.
  private JToggleButton activatedButton;

  // Elements for configuration panel
  // Global Replacements UI
  private JScrollPane globalReplacementScrollPane;
  private JTable globalReplacementTable;
  private JPanel globalReplacementsButtonPanel;
  private JButton addGlobalReplacementButton;
  private JButton editGlobalReplacementButton;
  private JButton deleteGlobalReplacementButton;

  // Replacements UI
  private JScrollPane replacementScrollPane;
  private JTable replacementTable;
  private JButton addReplacementButton;
  private JPanel replacementsButtonPanel;
  private JButton editReplacementButton;
  private JButton deleteReplacementButton;

  // Add Global Replacement Dialog UI
  private JPanel replacementPanel;

  private JComboBox<String> replacementTypeComboBox;
  private JTextField replacementMatchTextField;
  private JTextField replacementReplaceTextField;
  private JTextField replacementCommentTextField;
  private JCheckBox replacementIsRegexCheckBox;
  private JComboBox<String> replacementCountComboBox;

  private JLabel replacementMatchLabel;
  private JLabel replacementReplaceLabel;
  private JLabel replacementCommentLabel;
  private JLabel replacementTypeLabel;
  private JLabel replacementIsRegexLabel;
  private JLabel replacementCountLabel;

  private ReplacementTableModel globalReplacementTableModel;
  private ReplacementTableModel replacementTableModel;

  private Conditions conditions;

  public AutoRepeater() {
    this.callbacks = BurpExtender.getCallbacks();
    helpers = callbacks.getHelpers();
    gson = BurpExtender.getGson();
    conditions = new Conditions();
    createUI();
    setDefaultState();
    activatedButton.setSelected(true);
  }

  public AutoRepeater(JsonObject configurationJson) {
    this.callbacks = BurpExtender.getCallbacks();
    helpers = callbacks.getHelpers();
    gson = BurpExtender.getGson();
    conditions = new Conditions();
    createUI();
    if (configurationJson.get("isActivated").getAsBoolean()) {
      activatedButton.setSelected(true);
    }

    if (configurationJson.get("baseReplacements") != null) {
      for (JsonElement element : configurationJson.getAsJsonArray("baseReplacements")) {
        globalReplacementTableModel.addReplacement(gson.fromJson(element, Replacement.class));
      }
    }

    if (configurationJson.get("replacements") != null) {
      for (JsonElement element : configurationJson.getAsJsonArray("replacements")) {
        replacementTableModel.addReplacement(gson.fromJson(element, Replacement.class));
      }
    }

    if (configurationJson.get("conditions") != null) {
      for (JsonElement element : configurationJson.getAsJsonArray("conditions")) {
        conditions.getConditionTableModel().addCondition(gson.fromJson(element, Condition.class));
      }
    }
  }

  public JsonObject toJson() {
    JsonObject autoRepeaterJson = new JsonObject();
    autoRepeaterJson.addProperty("isActivated", activatedButton.isSelected());
    JsonArray baseReplacementsArray = new JsonArray();
    JsonArray replacementsArray = new JsonArray();
    JsonArray conditionsArray = new JsonArray();
    for (Condition c : conditions.getConditionTableModel().getConditions()) {
      conditionsArray.add(gson.toJsonTree(c));
    }
    for (Replacement r : globalReplacementTableModel.getReplacements()) {
      baseReplacementsArray.add(gson.toJsonTree(r));
    }
    for (Replacement r : replacementTableModel.getReplacements()) {
      replacementsArray.add(gson.toJsonTree(r));
    }
    autoRepeaterJson.add("baseReplacements", baseReplacementsArray);
    autoRepeaterJson.add("replacements", replacementsArray);
    autoRepeaterJson.add("conditions", conditionsArray);
    return autoRepeaterJson;
  }

  private void resetReplacementDialog() {
    replacementTypeComboBox.setSelectedIndex(0);
    replacementCountComboBox.setSelectedIndex(0);
    replacementMatchTextField.setText("");
    replacementReplaceTextField.setText("");
    replacementCommentTextField.setText("");
    replacementIsRegexCheckBox.setSelected(false);
  }

  public JSplitPane getUI() {
    return mainSplitPane;
  }

  private void createUI() {
    GridBagConstraints c;
    Border grayline = BorderFactory.createLineBorder(Color.GRAY);
    // main splitpane
    mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
    // splitpane that holds request and response viewers
    originalRequestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
    modifiedRequestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
    // This tabbedpane includes the configuration panels
    configurationTabbedPane = new JTabbedPane();
    // Initialize Activated Button
    activatedButton = new JToggleButton("Activate AutoRepeater");
    activatedButton.addChangeListener(e -> {
      if (activatedButton.isSelected()) {
        activatedButton.setText("Deactivate AutoRepeater");
      } else {
        activatedButton.setText("Activate AutoRepeater");
      }
    });

    Dimension activatedDimension = new Dimension(200, 20);
    activatedButton.setPreferredSize(activatedDimension);
    activatedButton.setMaximumSize(activatedDimension);
    activatedButton.setMinimumSize(activatedDimension);

    // GlobalReplacement Buttons
    // Populate Add Global Replacements Dialog
    replacementPanel = new JPanel();
    replacementPanel.setLayout(new GridBagLayout());
    replacementPanel.setPreferredSize(dialogDimension);

    c = new GridBagConstraints();

    replacementTypeComboBox = new JComboBox<>(Replacement.REPLACEMENT_TYPE_OPTIONS);
    replacementCountComboBox = new JComboBox<>(Replacement.REPLACEMENT_COUNT_OPTINONS);
    replacementMatchTextField = new JTextField();
    replacementReplaceTextField = new JTextField();
    replacementCommentTextField = new JTextField();
    replacementIsRegexCheckBox = new JCheckBox();

    replacementTypeComboBox.setPreferredSize(comboBoxDimension);
    replacementCountComboBox.setPreferredSize(comboBoxDimension);
    replacementMatchTextField.setPreferredSize(textFieldDimension);
    replacementReplaceTextField.setPreferredSize(textFieldDimension);
    replacementCommentTextField.setPreferredSize(textFieldDimension);

    replacementTypeLabel = new JLabel("Type: ");
    replacementMatchLabel = new JLabel("Match: ");
    replacementCountLabel = new JLabel("Which: ");
    replacementReplaceLabel = new JLabel("Replace: ");
    replacementCommentLabel = new JLabel("Comment: ");
    replacementIsRegexLabel = new JLabel("Regex Match: ");

    c.anchor = GridBagConstraints.WEST;
    c.gridx = 0;
    c.gridy = 0;
    replacementPanel.add(replacementTypeLabel, c);
    c.gridy = 1;
    replacementPanel.add(replacementMatchLabel, c);
    c.gridy = 2;
    replacementPanel.add(replacementReplaceLabel, c);
    c.gridy = 3;
    replacementPanel.add(replacementCountLabel, c);
    c.gridy = 4;
    replacementPanel.add(replacementCommentLabel, c);
    c.gridy = 5;
    replacementPanel.add(replacementIsRegexLabel, c);

    c.anchor = GridBagConstraints.EAST;
    c.fill = GridBagConstraints.HORIZONTAL;
    c.gridx = 1;
    c.gridy = 0;
    replacementPanel.add(replacementTypeComboBox, c);
    c.gridy = 1;
    replacementPanel.add(replacementMatchTextField, c);
    c.gridy = 2;
    replacementPanel.add(replacementReplaceTextField, c);
    c.gridy = 3;
    replacementPanel.add(replacementCountComboBox, c);
    c.gridy = 4;
    replacementPanel.add(replacementCommentTextField, c);
    c.gridy = 5;
    replacementPanel.add(replacementIsRegexCheckBox, c);

    // Initialize addGlobalReplacementButton
    addGlobalReplacementButton = new JButton("Add");
    addGlobalReplacementButton.setPreferredSize(buttonDimension);
    addGlobalReplacementButton.setMinimumSize(buttonDimension);
    addGlobalReplacementButton.setMaximumSize(buttonDimension);

    // Add new Global Replacement
    addGlobalReplacementButton.addActionListener(e -> {
      int result = JOptionPane.showConfirmDialog(mainSplitPane,
          replacementPanel,
          "Add Global Replacement",
          JOptionPane.OK_CANCEL_OPTION,
          JOptionPane.PLAIN_MESSAGE);
      if (result == JOptionPane.OK_OPTION) {
        Replacement newReplacement = new Replacement(
            (String) replacementTypeComboBox.getSelectedItem(),
            replacementMatchTextField.getText(),
            replacementReplaceTextField.getText(),
            (String) replacementCountComboBox.getSelectedItem(),
            replacementCommentTextField.getText(),
            replacementIsRegexCheckBox.isSelected()
        );

        globalReplacementTableModel.addReplacement(newReplacement);
        globalReplacementTableModel.fireTableDataChanged();
      }
      resetReplacementDialog();
    });

    //Initialize editGlobalReplacementButton
    editGlobalReplacementButton = new JButton("Edit");
    editGlobalReplacementButton.setPreferredSize(buttonDimension);
    editGlobalReplacementButton.setMinimumSize(buttonDimension);
    editGlobalReplacementButton.setMaximumSize(buttonDimension);

    // Edit selected Global Replacement
    editGlobalReplacementButton.addActionListener(e -> {
      int selectedRow = globalReplacementTable.getSelectedRow();
      Replacement tempReplacement = globalReplacementTableModel.getReplacement(selectedRow);

      replacementTypeComboBox.setSelectedItem(tempReplacement.getType());
      replacementMatchTextField.setText(tempReplacement.getMatch());
      replacementReplaceTextField.setText(tempReplacement.getReplace());
      replacementCountComboBox.setSelectedItem(tempReplacement.getWhich());
      replacementCommentTextField.setText(tempReplacement.getComment());
      replacementIsRegexCheckBox.setSelected(tempReplacement.isRegexMatch());

      int result = JOptionPane.showConfirmDialog(mainSplitPane,
          replacementPanel,
          "Edit Global Replacement",
          JOptionPane.OK_CANCEL_OPTION,
          JOptionPane.PLAIN_MESSAGE);
      if (result == JOptionPane.OK_OPTION) {
        Replacement newReplacement = new Replacement(
            (String) replacementTypeComboBox.getSelectedItem(),
            replacementMatchTextField.getText(),
            replacementReplaceTextField.getText(),
            (String) replacementCountComboBox.getSelectedItem(),
            replacementCommentTextField.getText(),
            replacementIsRegexCheckBox.isSelected()
        );
        globalReplacementTableModel.updateReplacement(selectedRow, newReplacement);
        globalReplacementTableModel.fireTableDataChanged();
      }
      resetReplacementDialog();
    });

    deleteGlobalReplacementButton = new JButton("Remove");
    deleteGlobalReplacementButton.setPreferredSize(buttonDimension);
    deleteGlobalReplacementButton.setMinimumSize(buttonDimension);
    deleteGlobalReplacementButton.setMaximumSize(buttonDimension);

    //Delete Global Replacement
    deleteGlobalReplacementButton.addActionListener(e -> {
      int selectedRow = globalReplacementTable.getSelectedRow();
      globalReplacementTableModel.deleteReplacement(selectedRow);
      globalReplacementTableModel.fireTableDataChanged();
    });

    globalReplacementsButtonPanel = new JPanel();
    globalReplacementsButtonPanel.setLayout(new GridBagLayout());
    globalReplacementsButtonPanel.setPreferredSize(new Dimension(75, 60));
    globalReplacementsButtonPanel.setMaximumSize(new Dimension(75, 60));
    globalReplacementsButtonPanel.setPreferredSize(new Dimension(75, 60));

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_END;
    c.gridx = 0;
    c.weightx = 1;

    globalReplacementsButtonPanel.add(addGlobalReplacementButton, c);
    globalReplacementsButtonPanel.add(editGlobalReplacementButton, c);
    globalReplacementsButtonPanel.add(deleteGlobalReplacementButton, c);

    // Replacement Buttons
    addReplacementButton = new JButton("Add");
    addReplacementButton.setPreferredSize(buttonDimension);
    addReplacementButton.setMinimumSize(buttonDimension);
    addReplacementButton.setMaximumSize(buttonDimension);

    // Add New Replacement
    addReplacementButton.addActionListener(e -> {
      int result = JOptionPane.showConfirmDialog(mainSplitPane,
          replacementPanel,
          "Add Replacement",
          JOptionPane.OK_CANCEL_OPTION,
          JOptionPane.PLAIN_MESSAGE);
      if (result == JOptionPane.OK_OPTION) {
        Replacement newReplacement = new Replacement(
            (String) replacementTypeComboBox.getSelectedItem(),
            replacementMatchTextField.getText(),
            replacementReplaceTextField.getText(),
            (String) replacementCountComboBox.getSelectedItem(),
            replacementCommentTextField.getText(),
            replacementIsRegexCheckBox.isSelected()
        );
        replacementTableModel.addReplacement(newReplacement);
        replacementTableModel.fireTableDataChanged();
      }
      resetReplacementDialog();
    });

    editReplacementButton = new JButton("Edit");
    editReplacementButton.setPreferredSize(buttonDimension);
    editReplacementButton.setMinimumSize(buttonDimension);
    editReplacementButton.setMaximumSize(buttonDimension);

    // Edit selected Replacement
    editReplacementButton.addActionListener(e -> {
      int selectedRow = replacementTable.getSelectedRow();
      Replacement tempReplacement = replacementTableModel.getReplacement(selectedRow);

      replacementTypeComboBox.setSelectedItem(tempReplacement.getType());
      replacementMatchTextField.setText(tempReplacement.getMatch());
      replacementReplaceTextField.setText(tempReplacement.getReplace());
      replacementCountComboBox.setSelectedItem(tempReplacement.getWhich());
      replacementCommentTextField.setText(tempReplacement.getComment());
      replacementIsRegexCheckBox.setSelected(tempReplacement.isRegexMatch());

      int result = JOptionPane.showConfirmDialog(mainSplitPane,
          replacementPanel,
          "Edit Replacement",
          JOptionPane.OK_CANCEL_OPTION,
          JOptionPane.PLAIN_MESSAGE);
      if (result == JOptionPane.OK_OPTION) {
        Replacement newReplacement = new Replacement(
            (String) replacementTypeComboBox.getSelectedItem(),
            replacementMatchTextField.getText(),
            replacementReplaceTextField.getText(),
            (String) replacementCountComboBox.getSelectedItem(),
            replacementCommentTextField.getText(),
            replacementIsRegexCheckBox.isSelected()
        );
        replacementTableModel.updateReplacement(selectedRow, newReplacement);
        replacementTableModel.fireTableDataChanged();
      }
      resetReplacementDialog();
    });

    deleteReplacementButton = new JButton("Remove");
    deleteReplacementButton.setPreferredSize(buttonDimension);
    deleteReplacementButton.setMinimumSize(buttonDimension);
    deleteReplacementButton.setMaximumSize(buttonDimension);

    //Delete Replacement
    deleteReplacementButton.addActionListener(e -> {
      int selectedRow = replacementTable.getSelectedRow();
      replacementTableModel.deleteReplacement(selectedRow);
      replacementTableModel.fireTableDataChanged();
    });

    replacementsButtonPanel = new JPanel();
    replacementsButtonPanel.setLayout(new GridBagLayout());
    replacementsButtonPanel.setPreferredSize(new Dimension(75, 60));

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_END;
    c.gridx = 0;
    c.weightx = 1;

    replacementsButtonPanel.add(addReplacementButton, c);
    replacementsButtonPanel.add(editReplacementButton, c);
    replacementsButtonPanel.add(deleteReplacementButton, c);

    // Global Replacement Table
    Dimension globalReplacementTableDimension = new Dimension(300, 40);
    globalReplacementTableModel = new ReplacementTableModel();
    globalReplacementTable = new JTable(globalReplacementTableModel);
    globalReplacementScrollPane = new JScrollPane(globalReplacementTable);

    // Panel containing globalReplacement options
    JPanel globalReplacementsPanel;
    globalReplacementsPanel = new JPanel();
    globalReplacementsPanel.setLayout(new GridBagLayout());

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.PAGE_START;
    c.gridx = 0;
    globalReplacementsPanel.add(globalReplacementsButtonPanel, c);

    c.fill = GridBagConstraints.BOTH;
    c.gridx = 1;
    c.weightx = 1;
    c.weighty = 1;
    globalReplacementsPanel.add(globalReplacementScrollPane, c);

    //Replacement Table
    Dimension replacementTableDimension = new Dimension(250, 40);
    replacementTableModel = new ReplacementTableModel();
    replacementTable = new JTable(replacementTableModel);
    replacementScrollPane = new JScrollPane(replacementTable);
    replacementScrollPane.setMinimumSize(replacementTableDimension);

    // Panel containing replacement options
    JPanel replacementsPanel;
    replacementsPanel = new JPanel();
    replacementsPanel.setLayout(new GridBagLayout());

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.PAGE_START;
    c.gridx = 0;
    replacementsPanel.add(replacementsButtonPanel, c);

    c.fill = GridBagConstraints.BOTH;
    c.weightx = 1;
    c.weighty = 1;
    c.gridx = 1;
    replacementsPanel.add(replacementScrollPane, c);

    //Condition Table
    //exportPanel = createExportPanel();

    configurationPane = new JPanel();
    configurationPane.setLayout(new GridBagLayout());
    Dimension configurationPaneDimension = new Dimension(400, 150);
    configurationPane.setMinimumSize(configurationPaneDimension);
    //configurationPane.setMaximumSize(configurationPaneDimension);
    configurationPane.setPreferredSize(configurationPaneDimension);
    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.NORTHWEST;
    configurationPane.add(activatedButton, c);
    c.fill = GridBagConstraints.BOTH;
    c.weightx = 1;
    c.weighty = 1;
    c.gridy = 1;

    configurationPane.add(configurationTabbedPane, c);
    configurationTabbedPane.addTab("Base Replacements", globalReplacementsPanel);
    configurationTabbedPane.addTab("Replacements", replacementsPanel);
    configurationTabbedPane.addTab("Conditions", conditions.getUI());
    //configurationTabbedPane.addTab("Export", exportPanel);
    configurationTabbedPane.addTab("Export", createExportPanel());
    configurationTabbedPane.setSelectedIndex(1);
    // table of log entries
    //logEntriesWithoutResponses = new ArrayList<>();
    logTableModel = new LogTableModel();
    logManager = new LogManager(logTableModel);
    logTable = new LogTable(logManager.getLogTableModel());
    logTable.setAutoCreateRowSorter(true);

    logTable.getColumnModel().getColumn(0).setPreferredWidth(5);
    logTable.getColumnModel().getColumn(1).setPreferredWidth(30);
    logTable.getColumnModel().getColumn(2).setPreferredWidth(250);
    logTable.getColumnModel().getColumn(3).setPreferredWidth(20);
    logTable.getColumnModel().getColumn(4).setPreferredWidth(20);
    logTable.getColumnModel().getColumn(5).setPreferredWidth(40);
    logTable.getColumnModel().getColumn(6).setPreferredWidth(40);
    logTable.getColumnModel().getColumn(7).setPreferredWidth(30);

    // Make every cell left aligned
    DefaultTableCellRenderer leftRenderer = new DefaultTableCellRenderer();
    leftRenderer.setHorizontalAlignment(JLabel.LEFT);
    for (int i = 0; i < 8; i++) {
      logTable.getColumnModel().getColumn(i).setCellRenderer(leftRenderer);
    }

    JScrollPane logTableScrollPane = new JScrollPane(logTable);
    logTableScrollPane.setMinimumSize(configurationPaneDimension);
    logTableScrollPane.setPreferredSize(new Dimension(10000, 10));

    // tabs with request/response viewers
    tabs = new JTabbedPane();

    tabs.addChangeListener(e -> {
      switch (tabs.getSelectedIndex()) {
        case 0:
          updateOriginalRequestResponseViewer();
          break;
        case 1:
          updateModifiedRequestResponseViewer();
          break;
        case 2:
          updateDiffViewer();
          break;
        default:
          updateLineDiffViewer();
          break;
      }
    });

    // Request / Response Viewers
    originalRequestViewer = callbacks.createMessageEditor(this, false);
    originalResponseViewer = callbacks.createMessageEditor(this, false);
    modifiedRequestViewer = callbacks.createMessageEditor(this, false);
    modifiedResponseViewer = callbacks.createMessageEditor(this, false);

    // Request / Response Labels
    originalRequestLabel = new JLabel("Request");
    originalResponseLabel = new JLabel("Response");
    modifiedRequestLabel = new JLabel("Request");
    modifiedResponseLabel = new JLabel("Response");

    JLabel diffRequestLabel = new JLabel("Request");
    JLabel diffResponseLabel = new JLabel("Response");

    JLabel lineDiffRequestLabel = new JLabel("Request");
    JLabel lineDiffResponseLabel = new JLabel("Response");

    originalRequestLabel.setForeground(Utils.getBurpOrange());
    originalResponseLabel.setForeground(Utils.getBurpOrange());
    modifiedRequestLabel.setForeground(Utils.getBurpOrange());
    modifiedResponseLabel.setForeground(Utils.getBurpOrange());
    diffRequestLabel.setForeground(Utils.getBurpOrange());
    diffResponseLabel.setForeground(Utils.getBurpOrange());
    lineDiffRequestLabel.setForeground(Utils.getBurpOrange());
    lineDiffResponseLabel.setForeground(Utils.getBurpOrange());

    originalRequestLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
    originalResponseLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
    modifiedRequestLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
    modifiedResponseLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
    diffRequestLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
    diffResponseLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
    lineDiffRequestLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
    lineDiffResponseLabel.setFont(new Font("SansSerif", Font.BOLD, 14));

    // Initialize JPanels that hold request/response viewers and labels
    originalRequestPanel = new JPanel();
    modifiedRequestPanel = new JPanel();

    originalResponsePanel = new JPanel();
    modifiedResponsePanel = new JPanel();

    originalRequestPanel.setLayout(new BoxLayout(originalRequestPanel, BoxLayout.PAGE_AXIS));
    modifiedRequestPanel.setLayout(new BoxLayout(modifiedRequestPanel, BoxLayout.PAGE_AXIS));
    originalResponsePanel.setLayout(new BoxLayout(originalResponsePanel, BoxLayout.PAGE_AXIS));
    modifiedResponsePanel.setLayout(new BoxLayout(modifiedResponsePanel, BoxLayout.PAGE_AXIS));

    // Diff viewer stuff
    JSplitPane diffSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

    JPanel requestDiffPanel = new JPanel();
    JPanel responseDiffPanel = new JPanel();

    requestDiffPanel.setPreferredSize(new Dimension(100000, 100000));
    responseDiffPanel.setPreferredSize(new Dimension(100000, 100000));

    requestDiffPanel.setLayout(new GridBagLayout());
    responseDiffPanel.setLayout(new GridBagLayout());

    requestComparer = new DiffViewerPane();
    responseComparer = new DiffViewerPane();

    requestComparerScrollPane = new JScrollPane(requestComparer);
    responseComparerScollPane = new JScrollPane(responseComparer);

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_START;
    requestDiffPanel.add(diffRequestLabel, c);
    c.gridy = 1;
    c.weightx = 1;
    c.weighty = 1;
    c.fill = GridBagConstraints.BOTH;
    requestDiffPanel.add(requestComparerScrollPane, c);

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_START;
    responseDiffPanel.add(diffResponseLabel, c);
    c.gridy = 1;
    c.weightx = 1;
    c.weighty = 1;
    c.fill = GridBagConstraints.BOTH;
    responseDiffPanel.add(responseComparerScollPane, c);

    // Line Diff Viewer Stuff
    JSplitPane lineDiffSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

    JPanel requestLineDiffPanel = new JPanel();
    JPanel responseLineDiffPanel = new JPanel();

    requestLineDiffPanel.setPreferredSize(new Dimension(100000, 100000));
    responseLineDiffPanel.setPreferredSize(new Dimension(100000, 100000));

    requestLineDiffPanel.setLayout(new GridBagLayout());
    responseLineDiffPanel.setLayout(new GridBagLayout());

    requestLineComparer = new DiffViewerPane();
    responseLineComparer = new DiffViewerPane();

    requestLineComparerScrollPane = new JScrollPane(requestLineComparer);
    responseLineComparerScollPane = new JScrollPane(responseLineComparer);

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_START;
    requestLineDiffPanel.add(lineDiffRequestLabel, c);
    c.gridy = 1;
    c.weightx = 1;
    c.weighty = 1;
    c.fill = GridBagConstraints.BOTH;
    requestLineDiffPanel.add(requestLineComparerScrollPane, c);

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_START;
    responseLineDiffPanel.add(lineDiffResponseLabel, c);
    c.gridy = 1;
    c.weightx = 1;
    c.weighty = 1;
    c.fill = GridBagConstraints.BOTH;
    responseLineDiffPanel.add(responseLineComparerScollPane, c);

    // Add Viewers
    originalRequestPanel.add(originalRequestLabel);
    originalRequestPanel.add(originalRequestViewer.getComponent());
    originalRequestPanel.setPreferredSize(new Dimension(100000, 100000));

    originalResponsePanel.add(originalResponseLabel);
    originalResponsePanel.add(originalResponseViewer.getComponent());
    originalResponsePanel.setPreferredSize(new Dimension(100000, 100000));

    modifiedRequestPanel.add(modifiedRequestLabel);
    modifiedRequestPanel.add(modifiedRequestViewer.getComponent());
    modifiedRequestPanel.setPreferredSize(new Dimension(100000, 100000));

    modifiedResponsePanel.add(modifiedResponseLabel);
    modifiedResponsePanel.add(modifiedResponseViewer.getComponent());
    modifiedResponsePanel.setPreferredSize(new Dimension(100000, 100000));

    // Add viewers to the original splitpane
    originalRequestResponseSplitPane.setLeftComponent(originalRequestPanel);
    originalRequestResponseSplitPane.setRightComponent(originalResponsePanel);

    originalRequestResponseSplitPane.setResizeWeight(0.50);
    tabs.addTab("Original", originalRequestResponseSplitPane);

    // Add viewers to the modified splitpane
    modifiedRequestResponseSplitPane.setLeftComponent(modifiedRequestPanel);
    modifiedRequestResponseSplitPane.setRightComponent(modifiedResponsePanel);
    modifiedRequestResponseSplitPane.setResizeWeight(0.5);
    tabs.addTab("Modified", modifiedRequestResponseSplitPane);

    // Add diff tab
    diffSplitPane.setLeftComponent(requestDiffPanel);
    diffSplitPane.setRightComponent(responseDiffPanel);
    diffSplitPane.setResizeWeight(0.50);
    tabs.addTab("Diff", diffSplitPane);

    //Add line diff tab
    lineDiffSplitPane.setLeftComponent(requestLineDiffPanel);
    lineDiffSplitPane.setRightComponent(responseLineDiffPanel);
    lineDiffSplitPane.setResizeWeight(0.50);
    tabs.addTab("Line Diff", lineDiffSplitPane);

    mainSplitPane.setResizeWeight(.00000000000001);
    mainSplitPane.setBottomComponent(tabs);

    // Split pane containing user interface components
    userInterfaceSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
    if (BurpExtender.showSettingsPanel()) {
      userInterfaceSplitPane.setRightComponent(configurationPane);
    }
    userInterfaceSplitPane.setLeftComponent(logTableScrollPane);
    userInterfaceSplitPane.setResizeWeight(1.0);
    mainSplitPane.setTopComponent(userInterfaceSplitPane);

    // Keep the split panes at the bottom the same size.
    originalRequestResponseSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
        pce -> {
          modifiedRequestResponseSplitPane.setDividerLocation(
              originalRequestResponseSplitPane.getDividerLocation());
          diffSplitPane.setDividerLocation(
              originalRequestResponseSplitPane.getDividerLocation());
          lineDiffSplitPane.setDividerLocation(
              originalRequestResponseSplitPane.getDividerLocation());
        }
    );
    modifiedRequestResponseSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
        pce -> {
          originalRequestResponseSplitPane.setDividerLocation(
              modifiedRequestResponseSplitPane.getDividerLocation());
          diffSplitPane.setDividerLocation(
              modifiedRequestResponseSplitPane.getDividerLocation());
          lineDiffSplitPane.setDividerLocation(
              modifiedRequestResponseSplitPane.getDividerLocation());
        }
    );
    diffSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
        pce -> {
          originalRequestResponseSplitPane.setDividerLocation(
              diffSplitPane.getDividerLocation());
          modifiedRequestResponseSplitPane.setDividerLocation(
              diffSplitPane.getDividerLocation());
          lineDiffSplitPane.setDividerLocation(
              diffSplitPane.getDividerLocation());
        }
    );
    lineDiffSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
        pce -> {
          originalRequestResponseSplitPane.setDividerLocation(
              lineDiffSplitPane.getDividerLocation());
          modifiedRequestResponseSplitPane.setDividerLocation(
              lineDiffSplitPane.getDividerLocation());
          diffSplitPane.setDividerLocation(
              lineDiffSplitPane.getDividerLocation());
        }
    );

    // I don't know what this actually does but I think it's correct
    callbacks.customizeUiComponent(mainSplitPane);
    callbacks.customizeUiComponent(logTable);
    callbacks.customizeUiComponent(logTableScrollPane);
    callbacks.customizeUiComponent(tabs);
    callbacks.customizeUiComponent(globalReplacementScrollPane);

    //helpPanel = new JPanel();
    //helpPanel.setLayout(new BorderLayout());
    //helpPanel.add(createHelpViewer());
  }

  private JEditorPane createHelpViewer() {
    JEditorPane helpViewer = new JEditorPane();
    helpViewer.setEditable(false);
    helpViewer.setContentType("text/html");
    String helpText = "<h1>AutoRepeater</h1>" +
        "<h2>Summary<h2>" +
        "<h2>Features<h2>" +
        "<h2>User Interface<h2>" +
        "<h2>Replacements<h2>" +
        "<h2>Conditions<h2>";

    helpViewer.setText(helpText);
    return helpViewer;
  }

  private JScrollPane createExportPanel() {
    final Dimension buttonDimension = new Dimension(120, 20);
    final Dimension comboBoxDimension = new Dimension(200, 20);

    final String[] EXPORT_OPTIONS = {"CSV", "JSON"};
    final String[] EXPORT_WHICH_OPTIONS = {"All Tab Logs", "Selected Tab Logs"};
    final String[] EXPORT_VALUE_OPTIONS = {"Log Entry", "Log Entry + Full HTTP Request"};
    final JComboBox<String> exportTypeComboBox = new JComboBox<>(EXPORT_OPTIONS);
    final JComboBox<String> exportWhichComboBox = new JComboBox<>(EXPORT_WHICH_OPTIONS);
    final JComboBox<String> exportValueComboBox = new JComboBox<>(EXPORT_VALUE_OPTIONS);
    final JButton exportButton = new JButton("Export Logs");
    final JFileChooser exportPathChooser = new JFileChooser();
    final JLabel exportLogsLabel = new JLabel("Export Logs");
    //final JFileChooser importPathChooser = new JFileChooser();

    // Log Exporting Related Things
    exportButton.setPreferredSize(buttonDimension);
    exportButton.setMaximumSize(buttonDimension);
    exportButton.setMaximumSize(buttonDimension);
    exportTypeComboBox.setPreferredSize(comboBoxDimension);
    exportTypeComboBox.setMinimumSize(comboBoxDimension);
    exportTypeComboBox.setMaximumSize(comboBoxDimension);
    exportWhichComboBox.setPreferredSize(comboBoxDimension);
    exportWhichComboBox.setMinimumSize(comboBoxDimension);
    exportWhichComboBox.setMaximumSize(comboBoxDimension);
    exportValueComboBox.setPreferredSize(comboBoxDimension);
    exportValueComboBox.setMinimumSize(comboBoxDimension);
    exportValueComboBox.setMaximumSize(comboBoxDimension);

    JPanel exportPanel = new JPanel();
    exportPanel.setLayout(new BoxLayout(exportPanel, BoxLayout.PAGE_AXIS));
    exportLogsLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
    exportPanel.add(exportLogsLabel);
    exportWhichComboBox.setAlignmentX(Component.LEFT_ALIGNMENT);
    exportPanel.add(exportWhichComboBox);
    exportValueComboBox.setAlignmentX(Component.LEFT_ALIGNMENT);
    exportPanel.add(exportValueComboBox);
    exportTypeComboBox.setAlignmentX(Component.LEFT_ALIGNMENT);
    exportPanel.add(exportTypeComboBox);
    JPanel buttonPanel = new JPanel();
    buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.LINE_AXIS));
    exportButton.setAlignmentX(Component.LEFT_ALIGNMENT);
    buttonPanel.add(exportButton);
    buttonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
    exportPanel.add(buttonPanel);

    exportButton.addActionListener((ActionEvent l) -> {
      int returnVal = exportPathChooser.showOpenDialog(mainSplitPane);
      if (returnVal == JFileChooser.APPROVE_OPTION) {
        File file = exportPathChooser.getSelectedFile();
        ArrayList<LogEntry> logEntries = new ArrayList<>();
        // Collect relevant entries
        if ((exportWhichComboBox.getSelectedItem()).equals("All Tab Logs")) {
          logEntries = logManager.getLogTableModel().getLog();
        } else if ((exportWhichComboBox.getSelectedItem()).equals("Selected Tab Logs")) {
          int[] selectedRows = logTable.getSelectedRows();
          for (int row : selectedRows) {
            logEntries.add(logManager.getLogEntry(logTable.convertRowIndexToModel(row)));
          }
        }
        //Determine if whole request should be exported or just the log contents
        boolean exportFullHttp = !((exportValueComboBox.getSelectedItem()).equals("Log Entry"));

        if ((exportTypeComboBox.getSelectedItem()).equals("CSV")) {
          try (PrintWriter out = new PrintWriter(file.getAbsolutePath())) {
            out.println(Utils.exportLogEntriesToCsv(logEntries, exportFullHttp));
          } catch (FileNotFoundException e) {
            e.printStackTrace();
          }
        } else if ((exportTypeComboBox.getSelectedItem()).equals("JSON")) {
          try (PrintWriter out = new PrintWriter(file.getAbsolutePath())) {
            out.println(Utils.exportLogEntriesToJson(logEntries, exportFullHttp));
          } catch (FileNotFoundException e) {
            e.printStackTrace();
          }
        }
      }
    });

    JLabel exportSettingsLabel = new JLabel("Export Settings");
    exportSettingsLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
    //exportPanel.add(exportLogsLabel);
    // TODO: Add export combobox to chose this tab or all tabs

    exportPanel.add(exportSettingsLabel);

    final String[] EXPORT_WHICH_TAB_SETTINGS_OPTIONS = {"This Tab", "Every Tab"};
    final JComboBox<String> exportWhichTabSettingsComboBox = new JComboBox<>(
        EXPORT_WHICH_TAB_SETTINGS_OPTIONS);
    exportWhichTabSettingsComboBox.setAlignmentX(Component.LEFT_ALIGNMENT);
    exportWhichTabSettingsComboBox.setPreferredSize(comboBoxDimension);
    exportWhichTabSettingsComboBox.setMinimumSize(comboBoxDimension);
    exportWhichTabSettingsComboBox.setMaximumSize(comboBoxDimension);

    final JButton exportSettingsButton = new JButton("Export Settings");
    exportSettingsButton.setPreferredSize(buttonDimension);
    exportSettingsButton.setMaximumSize(buttonDimension);
    exportSettingsButton.setMaximumSize(buttonDimension);
    exportSettingsButton.setAlignmentX(Component.LEFT_ALIGNMENT);

    exportSettingsButton.addActionListener((ActionEvent l) -> {
      int returnVal = exportPathChooser.showOpenDialog(mainSplitPane);
      if (returnVal == JFileChooser.APPROVE_OPTION) {
        File file = exportPathChooser.getSelectedFile();
        //ArrayList<LogEntry> logEntries = new ArrayList<>();
        // Collect relevant entries
        if ((exportWhichTabSettingsComboBox.getSelectedItem()).equals("This Tab")) {
          try (PrintWriter out = new PrintWriter(file.getAbsolutePath())) {
            out.println(BurpExtender.exportSave(this));
          } catch (FileNotFoundException e) {
            e.printStackTrace();
          }
        } else if ((exportWhichTabSettingsComboBox.getSelectedItem()).equals("Every Tab")) {
          try (PrintWriter out = new PrintWriter(file.getAbsolutePath())) {
            out.println(BurpExtender.exportSave());
          } catch (FileNotFoundException e) {
            e.printStackTrace();
          }
        }
      }
    });

    exportPanel.add(exportWhichTabSettingsComboBox);
    exportPanel.add(exportSettingsButton);

    final JLabel importSettingsLabel = new JLabel("Import Settings");
    importSettingsLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

    final String[] IMPORT_REPLACE_TABS_OPTIONS = {"Do Not Replace Tabs", "Replace Tabs"};
    final JComboBox<String> importReplaceTabsComboxBox = new JComboBox<>(
        IMPORT_REPLACE_TABS_OPTIONS);
    importReplaceTabsComboxBox.setAlignmentX(Component.LEFT_ALIGNMENT);
    importReplaceTabsComboxBox.setPreferredSize(comboBoxDimension);
    importReplaceTabsComboxBox.setMinimumSize(comboBoxDimension);
    importReplaceTabsComboxBox.setMaximumSize(comboBoxDimension);

    final JButton importButton = new JButton("Import Settings");
    importButton.setPreferredSize(buttonDimension);
    importButton.setMaximumSize(buttonDimension);
    importButton.setMaximumSize(buttonDimension);
    importButton.setAlignmentX(Component.LEFT_ALIGNMENT);

    importButton.addActionListener((ActionEvent l) -> {
      int returnVal = exportPathChooser.showOpenDialog(mainSplitPane);
      if (returnVal == JFileChooser.APPROVE_OPTION) {
        File file = exportPathChooser.getSelectedFile();
        String fileData = Utils.readFile(file);
        if (!fileData.equals("")) {
          if ((importReplaceTabsComboxBox.getSelectedItem()).equals("Do Not Replace Tabs")) {
            BurpExtender.initializeFromSave(fileData, false);
          } else if ((importReplaceTabsComboxBox.getSelectedItem()).equals("Replace Tabs")) {
            BurpExtender.getCallbacks().printOutput("Removing Tabs");
            BurpExtender.initializeFromSave(fileData, true);
          }
        }
      }
    });
    exportPanel.add(importSettingsLabel);
    exportPanel.add(importReplaceTabsComboxBox);
    exportPanel.add(importButton);
    return new JScrollPane(exportPanel);
  }

  private void setDefaultState() {
    conditions.getConditionTableModel().addCondition(new Condition(
        "",
        "Sent From Tool",
        "Burp",
        ""
    ));

    conditions.getConditionTableModel().addCondition(new Condition(
        "Or",
        "Request",
        "Contains Parameters",
        "",
        false
    ));

    conditions.getConditionTableModel().addCondition(new Condition(
        "Or",
        "HTTP Method",
        "Does Not Match",
        "(GET|POST)",
        false
    ));

    conditions.getConditionTableModel().addCondition(new Condition(
        "And",
        "URL",
        "Is In Scope",
        "",
        false
    ));
  }

  public void modifyAndSendRequestAndLog(
      int toolFlag,
      boolean messageIsRequest,
      IHttpRequestResponse messageInfo,
      boolean isSentToAutoRepeater) {

    //Although this isn't optimal, i'm generating the modified requests when a response is received.
    //Burp doesn't have a nice way to tie arbitrary sent requests with a response received later.
    //Doing it on request requires a ton of additional book keeping that i don't think warrants the benefits
    if (((!messageIsRequest || isSentToAutoRepeater)
        && activatedButton.isSelected()
        && toolFlag != BurpExtender.getCallbacks().TOOL_EXTENDER)) {
      boolean meetsConditions = false;
      if (conditions.getConditionTableModel().getConditions().size() == 0) {
        meetsConditions = true;
      } else {
        if (conditions.getConditionTableModel().getConditions()
            .stream()
            .filter(Condition::isEnabled)
            .filter(c -> c.getBooleanOperator().equals("Or"))
            .anyMatch(c -> c.checkCondition(toolFlag, messageInfo))) {
          meetsConditions = true;
        }
        if (conditions.getConditionTableModel().getConditions()
            .stream()
            .filter(Condition::isEnabled)
            .filter(
                c -> c.getBooleanOperator().equals("And") || c.getBooleanOperator().equals(""))
            .allMatch(c -> c.checkCondition(toolFlag, messageInfo))) {
          meetsConditions = true;
        }
      }
      if (meetsConditions) {
        // Create a set to store each new unique request in
        HashSet<IHttpRequestResponse> requestSet = new HashSet<>();
        IHttpRequestResponse baseReplacedRequestResponse = Utils
            .cloneIHttpRequestResponse(messageInfo);
        // Perform all the base replacements on the captured request
        for (Replacement globalReplacement : globalReplacementTableModel.getReplacements()) {
          baseReplacedRequestResponse.setRequest(
              globalReplacement.performReplacement(baseReplacedRequestResponse));
        }
        //Add the base replaced request to the request set
        if(replacementTableModel.getReplacements().size() == 0) {
          requestSet.add(baseReplacedRequestResponse);
        }
        // Perform all the separate replacements on the request+base replacements and add them to the set
        for (Replacement replacement : replacementTableModel.getReplacements()) {
          IHttpRequestResponse newHttpRequest = Utils
              .cloneIHttpRequestResponse(baseReplacedRequestResponse);
          newHttpRequest.setRequest(replacement.performReplacement(newHttpRequest));
          requestSet.add(newHttpRequest);
        }
        // Perform every unique request and log
        for (IHttpRequestResponse request : requestSet) {
          if (!Arrays.equals(request.getRequest(), messageInfo.getRequest())) {
            IHttpRequestResponse modifiedRequestResponse =
                callbacks.makeHttpRequest(messageInfo.getHttpService(), request.getRequest());
            int row = logManager.getRowCount();
            LogEntry newLogEntry = new LogEntry(
                row + 1,
                callbacks.saveBuffersToTempFiles(messageInfo),
                callbacks.saveBuffersToTempFiles(modifiedRequestResponse));
            logManager.addEntry(newLogEntry);
            logManager.fireTableRowsUpdated(row, row);
            //BurpExtender.highlightTab();
          }
        }
      }
    }
  }

  public void toggleConfigurationPane(boolean visible) {
    if (visible) {
      userInterfaceSplitPane.setRightComponent(configurationPane);
    } else {
      userInterfaceSplitPane.remove(configurationPane);
    }
  }

  // Implement IMessageEditorController
  @Override
  public byte[] getRequest() {
    switch (tabs.getSelectedIndex()) {
      case 0:
        return currentOriginalRequestResponse.getRequest();
      case 1:
        return currentModifiedRequestResponse.getRequest();
      default:
        return new byte[0];
    }
  }

  @Override
  public byte[] getResponse() {
    switch (tabs.getSelectedIndex()) {
      case 0:
        return currentOriginalRequestResponse.getResponse();
      case 1:
        return currentModifiedRequestResponse.getResponse();
      default:
        return new byte[0];
    }
  }

  @Override
  public IHttpService getHttpService() {
    switch (tabs.getSelectedIndex()) {
      case 0:
        return currentOriginalRequestResponse.getHttpService();
      case 1:
        return currentModifiedRequestResponse.getHttpService();
      default:
        return null;
    }
  }

  private void updateOriginalRequestResponseViewer() {
    SwingUtilities.invokeLater(() -> {
      // Set Original Request Viewer
      if (originalRequest != null) {
        originalRequestViewer.setMessage(originalRequest, true);
      } else {
        originalRequestViewer.setMessage(new byte[0], true);
      }

      // Set Original Response Viewer
      if (originalResponse != null) {
        originalResponseViewer.setMessage(originalResponse, false);
      } else {
        originalResponseViewer.setMessage(new byte[0], false);
      }
    });
  }

  private void updateModifiedRequestResponseViewer() {
    SwingUtilities.invokeLater(() -> {
      // Set Modified Request Viewer
      if (modifiedRequest != null) {
        modifiedRequestViewer.setMessage(modifiedRequest, true);
      } else {
        modifiedRequestViewer.setMessage(new byte[0], true);
      }

      // Set Modified Response Viewer
      if (modifiedResponse != null) {
        modifiedResponseViewer.setMessage(modifiedResponse, false);
      } else {
        modifiedResponseViewer.setMessage(new byte[0], false);
      }
    });
  }

  private void updateDiffViewer() {
    SwingUtilities.invokeLater(() -> {
      if (originalRequest != null && modifiedRequest != null) {
        requestComparer.setText(requestDiff);
        requestComparer.setCaretPosition(0);
      } else {
        requestComparer.setText("");
      }

      // Set Response Diff Viewer
      if (originalResponse != null && modifiedResponse != null) {
        responseComparer.setText(responseDiff);
        responseComparer.setCaretPosition(0);
      } else {
        responseComparer.setText("");
      }
    });
  }

  private void updateLineDiffViewer() {
    SwingUtilities.invokeLater(() -> {
      if (originalRequest != null && modifiedRequest != null) {
        requestLineComparer.setText(requestLineDiff);
        requestLineComparer.setCaretPosition(0);
      } else {
        requestLineComparer.setText("");
      }

      // Set Response Diff Viewer
      if (originalResponse != null && modifiedResponse != null) {
        responseLineComparer.setText(responseLineDiff);
        responseLineComparer.setCaretPosition(0);
      } else {
        responseLineComparer.setText("");
      }
    });
  }

  private void updateRequestViewers() {
    switch (tabs.getSelectedIndex()) {
      case 0:
        updateOriginalRequestResponseViewer();
        break;
      case 1:
        updateModifiedRequestResponseViewer();
        break;
      case 2:
        updateDiffViewer();
        break;
      default:
        updateLineDiffViewer();
        break;
    }
  }

  // JTable for Viewing Logs
  public class LogTable extends JTable {

    public LogTable(TableModel tableModel) {
      super(tableModel);
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
      super.changeSelection(row, col, toggle, extend);
      // show the log entry for the selected row
      LogEntry logEntry = logManager.getLogEntry(convertRowIndexToModel(row));

      //final LogTable _this = this;
      this.addMouseListener(new MouseAdapter() {
        @Override
        public void mouseClicked(MouseEvent e) {
          onMouseEvent(e);
        }

        @Override
        public void mouseReleased(MouseEvent e) {
          onMouseEvent(e);
        }

        @Override
        public void mousePressed(MouseEvent e) {
          onMouseEvent(e);
        }

        // Event for clearing the logs
        private void onMouseEvent(MouseEvent e) {
          if (SwingUtilities.isRightMouseButton(e)) {
            Point p = e.getPoint();
            final int row = convertRowIndexToModel(rowAtPoint(p));
            final int col = convertColumnIndexToModel(columnAtPoint(p));
            if (e.isPopupTrigger() && e.getComponent() instanceof JTable) {
              getSelectionModel().setSelectionInterval(row, row);
              new LogEntryMenu(logManager, logTable, row, col)
                  .show(e.getComponent(), e.getX(), e.getY());
            }
          }
        }
      });

      // There's a delay while changing selections because setting the diff viewer is slow.
      new Thread(() -> {
        originalRequest = logEntry.getOriginalRequestResponse().getRequest();
        originalResponse = logEntry.getOriginalRequestResponse().getResponse();
        modifiedRequest = logEntry.getModifiedRequestResponse().getRequest();
        modifiedResponse = logEntry.getModifiedRequestResponse().getResponse();
        currentOriginalRequestResponse = logEntry.getOriginalRequestResponse();
        currentModifiedRequestResponse = logEntry.getModifiedRequestResponse();

        new Thread(() -> {
          requestDiff = HttpComparer
              .diffText(new String(originalRequest), new String(modifiedRequest));
          updateRequestViewers();
        }).start();
        new Thread(() -> {
          responseDiff = HttpComparer
              .diffText(new String(originalResponse), new String(modifiedResponse));
          updateRequestViewers();
        }).start();
        new Thread(() -> {
          requestLineDiff = HttpComparer
              .diffLines(new String(originalRequest), new String(modifiedRequest));
          updateRequestViewers();
        }).start();
        new Thread(() -> {
          responseLineDiff = HttpComparer
              .diffLines(new String(originalResponse), new String(modifiedResponse));
          updateRequestViewers();
        }).start();
        updateRequestViewers();
        // Hack to speed up the ui
      }).start();
    }
  }
}
