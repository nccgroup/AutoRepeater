package burp;


import burp.Conditions.Condition;
import burp.Conditions.ConditionTableModel;
import burp.Conditions.Conditions;
import burp.Filter.Filter;
import burp.Filter.FilterTableModel;
import burp.Filter.Filters;
import burp.Highlighter.HighlighterTableModel;
import burp.Highlighter.HighlighterUITableModel;
import burp.Highlighter.Highlighters;
import burp.Logs.LogEntry;
import burp.Logs.LogEntryMenu;
import burp.Logs.LogManager;
import burp.Logs.LogTableModel;
import burp.Replacements.Replacement;
import burp.Replacements.ReplacementTableModel;
import burp.Replacements.Replacements;
import burp.Utils.DiffViewerPane;
import burp.Utils.HttpComparer;
import burp.Utils.Utils;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Arrays;
import java.util.HashSet;
import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableModel;

public class AutoRepeater implements IMessageEditorController {

  // UI Component Dimensions
  public static final Dimension dialogDimension = new Dimension(450, 140);
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
  private LogManager logManager;

  // The current item selected in the log table
  private IHttpRequestResponsePersisted currentOriginalRequestResponse;
  private IHttpRequestResponsePersisted currentModifiedRequestResponse;

  // The tabbed pane that holds the configuration options
  private JPanel configurationPane;
  private JTabbedPane configurationTabbedPane;

  // The button that indicates weather AutoRepeater is active.
  private JToggleButton activatedButton;

  // Elements for configuration panel
  private Conditions conditions;
  private ConditionTableModel conditionsTableModel;

  private Replacements replacements;
  private ReplacementTableModel replacementsTableModel;

  private Replacements baseReplacements;
  private ReplacementTableModel baseReplacementsTableModel;

  private Filters filters;
  private FilterTableModel filterTableModel;

  private Highlighters highlighters;
  private HighlighterUITableModel highlighterUITableModel;

  public AutoRepeater() {
    this.callbacks = BurpExtender.getCallbacks();
    helpers = callbacks.getHelpers();
    gson = BurpExtender.getGson();
    conditions = new Conditions();
    conditionsTableModel = conditions.getConditionTableModel();
    replacements = new Replacements();
    replacementsTableModel = replacements.getReplacementTableModel();
    baseReplacements = new Replacements();
    baseReplacementsTableModel = baseReplacements.getReplacementTableModel();
    logManager = new LogManager();
    logTable = new LogTable(logManager.getLogTableModel());
    filters = new Filters(logManager);
    filterTableModel = filters.getFilterTableModel();
    highlighters = new Highlighters(logManager, logTable);
    highlighterUITableModel = highlighters.getHighlighterUITableModel();
    createUI();
    setDefaultState();
    activatedButton.setSelected(true);
  }

  public AutoRepeater(JsonObject configurationJson) {
    this();
    // clear out the conditions from the default constructor
    conditionsTableModel.clear();
    filterTableModel.clear();
    // Initialize singular properties
    if (configurationJson.get("isActivated") != null) {
      activatedButton.setSelected(configurationJson.get("isActivated").getAsBoolean());
    }
    if (configurationJson.get("isWhitelistFilter") != null) {
      filters.setWhitelist(configurationJson.get("isWhitelistFilter").getAsBoolean());
    }
    // Initialize lists
    if (configurationJson.get("baseReplacements") != null) {
      for (JsonElement element : configurationJson.getAsJsonArray("baseReplacements")) {
        baseReplacementsTableModel.addReplacement(gson.fromJson(element, Replacement.class));
      }
    }
    if (configurationJson.get("replacements") != null) {
      for (JsonElement element : configurationJson.getAsJsonArray("replacements")) {
        replacementsTableModel.addReplacement(gson.fromJson(element, Replacement.class));
      }
    }
    if (configurationJson.get("conditions") != null) {
      for (JsonElement element : configurationJson.getAsJsonArray("conditions")) {
        conditionsTableModel.add(gson.fromJson(element, Condition.class));
      }
    }
    if (configurationJson.get("filters") != null) {
      for (JsonElement element : configurationJson.getAsJsonArray("filters")) {
        filterTableModel.add(gson.fromJson(element, Filter.class));
      }
    }
    // If something was empty, put in the default values
    if(conditionsTableModel.getConditions().size() == 0) {
      setDefaultConditions();
    }
    if(filterTableModel.getFilters().size() == 0) {
      setDefaultFilters();
    }
  }

  public void setDefaultConditions() {
    conditionsTableModel.add(new Condition(
        "",
        "Sent From Tool",
        "Burp",
        ""
    ));

    conditionsTableModel.add(new Condition(
        "Or",
        "Request",
        "Contains Parameters",
        "",
        false
    ));

    conditionsTableModel.add(new Condition(
        "Or",
        "HTTP Method",
        "Does Not Match",
        "(GET|POST)",
        false
    ));

    conditionsTableModel.add(new Condition(
        "And",
        "URL",
        "Is In Scope",
        "",
        false
    ));
  }

  public void setDefaultFilters() {
    filterTableModel.add(new Filter(
        "",
        "Original",
        "Sent From Tool",
        "Burp",
        ""
    ));
  }

  private void setDefaultState() {
    setDefaultConditions();
    setDefaultFilters();
  }

  public JsonObject toJson() {
    JsonObject autoRepeaterJson = new JsonObject();
    // Add Static Properties
    autoRepeaterJson.addProperty("isActivated", activatedButton.isSelected());
    autoRepeaterJson.addProperty("isWhitelistFilter", filters.isWhitelist());
    // Add Arrays
    JsonArray baseReplacementsArray = new JsonArray();
    JsonArray replacementsArray = new JsonArray();
    JsonArray conditionsArray = new JsonArray();
    JsonArray filtersArray = new JsonArray();
    for (Condition c : conditionsTableModel.getConditions()) {
      conditionsArray.add(gson.toJsonTree(c));
    }
    for (Replacement r : baseReplacementsTableModel.getReplacements()) {
      baseReplacementsArray.add(gson.toJsonTree(r));
    }
    for (Replacement r : replacementsTableModel.getReplacements()) {
      replacementsArray.add(gson.toJsonTree(r));
    }
    for (Filter f : filterTableModel.getFilters()) {
      filtersArray.add(gson.toJsonTree(f));
    }
    autoRepeaterJson.add("baseReplacements", baseReplacementsArray);
    autoRepeaterJson.add("replacements", replacementsArray);
    autoRepeaterJson.add("conditions", conditionsArray);
    autoRepeaterJson.add("filters", filtersArray);
    return autoRepeaterJson;
  }

  public JSplitPane getUI() {
    return mainSplitPane;
  }

  public LogTable getLogTable() {
    return logTable;
  }

  public LogManager getLogManager() {
    return logManager;
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

    configurationPane = new JPanel();
    configurationPane.setLayout(new GridBagLayout());
    Dimension configurationPaneDimension = new Dimension(470, 150);
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
    configurationTabbedPane.addTab("Base Replacements", baseReplacements.getUI());
    configurationTabbedPane.addTab("Replacements", replacements.getUI());
    configurationTabbedPane.addTab("Conditions", conditions.getUI());
    configurationTabbedPane.addTab("Log Filter", filters.getUI());
    configurationTabbedPane.addTab("Log Highlighter", highlighters.getUI());
    configurationTabbedPane.setSelectedIndex(1);
    // table of log entries
    logTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
      @Override
      public Component getTableCellRendererComponent(
          JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        Component c =
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        c.setBackground(
            logManager.getLogTableModel().getLogEntry(
                logTable.convertRowIndexToModel(row)).getBackgroundColor());
        if(isSelected) {
          c.setBackground(c.getBackground().darker());
        }

        //DefaultTableCellRenderer leftRenderer = new DefaultTableCellRenderer();
        //leftRenderer.setHorizontalAlignment(JLabel.LEFT);
        //for (int i = 0; i < 8; i++) {
        //  logTable.getColumnModel().getColumn(i).setCellRenderer(leftRenderer);
        //}
        //c.setBackground(Color.RED);
        //System.out.println(logTableModel.getLogEntry(row).getBackgroundColor().toString());
        return c;
      }
    });

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

    userInterfaceSplitPane.setRightComponent(configurationPane);
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
  }

  public void modifyAndSendRequestAndLog(
      int toolFlag,
      boolean messageIsRequest,
      IHttpRequestResponse messageInfo ) {
    if (!messageIsRequest
        && activatedButton.isSelected()
        && toolFlag != BurpExtender.getCallbacks().TOOL_EXTENDER) {
      boolean meetsConditions = conditionsTableModel.check(toolFlag, messageInfo);
      if (meetsConditions) {
        // Create a set to store each new unique request in
        HashSet<IHttpRequestResponse> requestSet = new HashSet<>();
        IHttpRequestResponse baseReplacedRequestResponse = Utils
            .cloneIHttpRequestResponse(messageInfo);
        // Perform all the base replacements on the captured request
        for (Replacement globalReplacement : baseReplacementsTableModel.getReplacements()) {
          baseReplacedRequestResponse.setRequest(
              globalReplacement.performReplacement(baseReplacedRequestResponse));
        }
        //Add the base replaced request to the request set
        if(replacementsTableModel.getReplacements().size() == 0) {
          requestSet.add(baseReplacedRequestResponse);
        }
        // Perform all the separate replacements on the request+base replacements and add them to the set
        for (Replacement replacement : replacementsTableModel.getReplacements()) {
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
                logManager.getLogTableModel().getLogCount() + 1,
                toolFlag,
                callbacks.saveBuffersToTempFiles(messageInfo),
                callbacks.saveBuffersToTempFiles(modifiedRequestResponse));
            // Highlight the rows
            highlighters.highlight(newLogEntry);
            logManager.addEntry(newLogEntry, filters);
            logManager.fireTableRowsUpdated(row, row);
          }
        }
      }
    }
  }

  public LogTableModel getLogTableModel() {
    return logManager.getLogTableModel();
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
