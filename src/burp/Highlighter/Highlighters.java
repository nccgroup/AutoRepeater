package burp.Highlighter;

import burp.AutoRepeater;
import burp.BurpExtender;
import burp.Logs.LogEntry;
import burp.Logs.LogManager;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;

public class Highlighters {
  // Highlighters UI
  JPanel highlightsPanel;
  private JPanel highlightFilterPanel;
  private JScrollPane highlightFilterScrollPane;
  private JTable highlightFilterTable;
  private JButton addHighlighterButton;
  private JButton editHighlighterButton;
  private JButton deleteHighlighterButton;

  // Highlighters Popup UI
  private JComboBox<String> booleanOperatorComboBox;
  private JComboBox<String> originalOrModifiedComboBox;
  private JComboBox<String> matchTypeComboBox;
  private JComboBox<String> matchRelationshipComboBox;
  private JTextField matchHighlighterTextField;

  // Highlighters Menu UI
  private JLabel colorLabel;

  private JLabel booleanOperatorLabel;
  private JLabel originalOrModifiedLabel;
  private JLabel matchTypeLabel;
  private JLabel matchRelationshipLabel;
  private JLabel matchHighlighterLabel;

  private HighlighterTableModel highlighterTableModel;
  private HighlighterUITableModel highlighterUITableModel;
  private LogManager logManager;

  public Highlighters(LogManager logManager) {
    highlighterUITableModel = new HighlighterUITableModel();
    this.logManager = logManager;
    highlightsPanel = createMenuUI();
  }

  public HighlighterTableModel getHighlighterTableModel() { return highlighterTableModel; }
  public JPanel getUI() { return highlightsPanel; }

  public boolean highlight(LogEntry logEntry) {
    return highlighterTableModel.check(logEntry);
  }

  private JPanel createMenuUI() {
    GridBagConstraints c;

    JPanel menuPanel = new JPanel();
    JButton addHighlighterButton = new JButton("Add");
    JButton editHighlighterButton = new JButton("Edit");
    JButton deleteHighlighterButton = new JButton("Remove");
    JPanel buttonsPanel = new JPanel();
    JTable menuTable = new JTable(highlighterUITableModel);

    addHighlighterButton.setPreferredSize(AutoRepeater.buttonDimension);
    editHighlighterButton.setPreferredSize(AutoRepeater.buttonDimension);
    deleteHighlighterButton.setPreferredSize(AutoRepeater.buttonDimension);
    addHighlighterButton.setMinimumSize(AutoRepeater.buttonDimension);
    editHighlighterButton.setMinimumSize(AutoRepeater.buttonDimension);
    deleteHighlighterButton.setMinimumSize(AutoRepeater.buttonDimension);
    addHighlighterButton.setMaximumSize(AutoRepeater.buttonDimension);
    editHighlighterButton.setMaximumSize(AutoRepeater.buttonDimension);
    deleteHighlighterButton.setMaximumSize(AutoRepeater.buttonDimension);
    buttonsPanel.setPreferredSize(AutoRepeater.buttonPanelDimension);

    buttonsPanel.setLayout(new GridBagLayout());
    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_START;
    c.gridx = 0;
    c.weightx = 0;
    buttonsPanel.add(addHighlighterButton, c);
    buttonsPanel.add(editHighlighterButton, c);
    buttonsPanel.add(deleteHighlighterButton, c);

    JScrollPane menuScrollPane = new JScrollPane(menuTable);

    // Panel containing filter options
    menuPanel.setLayout(new GridBagLayout());
    c = new GridBagConstraints();
    c.ipady = 0;
    c.anchor = GridBagConstraints.PAGE_START;
    c.gridx = 0;
    c.gridy = 1;
    menuPanel.add(buttonsPanel, c);
    c.fill = GridBagConstraints.BOTH;
    c.weightx = 1;
    c.weighty = 1;
    c.gridx = 1;
    menuPanel.add(menuScrollPane, c);

    addHighlighterButton.addActionListener(l -> {
      int result = JOptionPane.showConfirmDialog(
          BurpExtender.getParentTabbedPane(),
          createHighlighterUI(),
          "Add Highlighter",
          JOptionPane.OK_CANCEL_OPTION,
          JOptionPane.PLAIN_MESSAGE);
      if (result == JOptionPane.OK_OPTION) {
        highlighterUITableModel.add(new HighlighterTableModel(highlighterTableModel));
        highlighterUITableModel.fireTableDataChanged();
      }
    });
    return menuPanel;
  }

  // This is the UI for the highlighter pop up with the table
  private JPanel createHighlighterUI() {
    GridBagConstraints c;

    JPanel menuPanel = new JPanel();
    JButton addHighlighterButton = new JButton("Add");
    JButton editHighlighterButton = new JButton("Edit");
    JButton deleteHighlighterButton = new JButton("Remove");
    JPanel buttonsPanel = new JPanel();
    highlighterTableModel = new HighlighterTableModel();
    JTable menuTable = new JTable(highlighterTableModel);

    highlighterTableModel.add(new Highlighter("", "Original","URL", "Matches", ""));
    highlighterTableModel.fireTableDataChanged();

    JLabel colorComboBoxLabel = new JLabel("Highlight Color: ");
    JComboBox<String> colorComboBox = new JComboBox<>(Highlighter.COLOR_NAMES);
    colorComboBox.setRenderer((list, value, index, isSelected, cellHasFocus) -> {
      DefaultListCellRenderer defaultListCellRenderer = new DefaultListCellRenderer();
      JLabel label = (JLabel) defaultListCellRenderer.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
      label.setOpaque(true);
      for (int i = 0; i < Highlighter.COLOR_NAMES.length; i++) {
        if (value.equals(Highlighter.COLOR_NAMES[i])) {
          label.setBackground(Highlighter.COLORS[i]);
        }
      }
      return label;
    });
    colorComboBox.addActionListener(e -> highlighterTableModel.setColor((String)colorComboBox.getSelectedItem()));
    colorComboBox.setPreferredSize(AutoRepeater.comboBoxDimension);
    colorComboBox.setMinimumSize(AutoRepeater.comboBoxDimension);
    colorComboBox.setMaximumSize(AutoRepeater.comboBoxDimension);

    JPanel colorComboBoxPanel = new JPanel();
    colorComboBoxPanel.setLayout(new GridBagLayout());
    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_START;
    c.gridx = 0;
    c.weightx = 0;
    colorComboBoxPanel.add(colorComboBoxLabel, c);
    c.gridx = 1;
    colorComboBoxPanel.add(colorComboBox, c);

    addHighlighterButton.setPreferredSize(AutoRepeater.buttonDimension);
    editHighlighterButton.setPreferredSize(AutoRepeater.buttonDimension);
    deleteHighlighterButton.setPreferredSize(AutoRepeater.buttonDimension);
    addHighlighterButton.setMinimumSize(AutoRepeater.buttonDimension);
    editHighlighterButton.setMinimumSize(AutoRepeater.buttonDimension);
    deleteHighlighterButton.setMinimumSize(AutoRepeater.buttonDimension);
    addHighlighterButton.setMaximumSize(AutoRepeater.buttonDimension);
    editHighlighterButton.setMaximumSize(AutoRepeater.buttonDimension);
    deleteHighlighterButton.setMaximumSize(AutoRepeater.buttonDimension);
    buttonsPanel.setPreferredSize(AutoRepeater.buttonPanelDimension);

    buttonsPanel.setLayout(new GridBagLayout());
    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_START;
    c.gridx = 0;
    c.weightx = 0;
    buttonsPanel.add(addHighlighterButton, c);
    buttonsPanel.add(editHighlighterButton, c);
    buttonsPanel.add(deleteHighlighterButton, c);

    JScrollPane menuScrollPane = new JScrollPane(menuTable);

    // Panel containing filter options
    menuPanel.setLayout(new GridBagLayout());
    c = new GridBagConstraints();
    c.ipady = 0;
    c.anchor = GridBagConstraints.PAGE_START;
    c.gridx = 0;
    c.gridy = 1;
    menuPanel.add(buttonsPanel, c);
    c.fill = GridBagConstraints.BOTH;
    c.weightx = 1;
    c.weighty = 1;
    c.gridx = 1;
    menuPanel.add(menuScrollPane, c);

    JPanel outputPanel = new JPanel();
    outputPanel.setLayout(new BoxLayout(outputPanel, BoxLayout.PAGE_AXIS));
    outputPanel.add(colorComboBoxPanel);
    outputPanel.add(menuPanel);
    outputPanel.setPreferredSize(AutoRepeater.dialogDimension);
    outputPanel.setMaximumSize(AutoRepeater.dialogDimension);
    outputPanel.setMinimumSize(AutoRepeater.dialogDimension);

    // Button Actions
    addHighlighterButton.addActionListener(l -> {
      int result = JOptionPane.showConfirmDialog(
          BurpExtender.getParentTabbedPane(),
          createHighlightEditorUI(),
          "Edit Highlighter",
          JOptionPane.OK_CANCEL_OPTION,
          JOptionPane.PLAIN_MESSAGE);
      if (result == JOptionPane.OK_OPTION) {
        highlighterTableModel.add(
            new Highlighter(
            (String) booleanOperatorComboBox.getSelectedItem(),
            (String) originalOrModifiedComboBox.getSelectedItem(),
            (String) matchTypeComboBox.getSelectedItem(),
            (String) matchRelationshipComboBox.getSelectedItem(),
            matchHighlighterTextField.getText(),
            true
            )
        );
        highlighterTableModel.fireTableDataChanged();
      }
    });
    editHighlighterButton.addActionListener(l -> {
      int result = JOptionPane.showConfirmDialog(
          BurpExtender.getParentTabbedPane(),
          createHighlightEditorUI(),
          "Edit Highlighter",
          JOptionPane.OK_CANCEL_OPTION,
          JOptionPane.PLAIN_MESSAGE);
      if (result == JOptionPane.OK_OPTION) {
        Highlighter newHighlighter = new Highlighter(
            (String) booleanOperatorComboBox.getSelectedItem(),
            (String) originalOrModifiedComboBox.getSelectedItem(),
            (String) matchTypeComboBox.getSelectedItem(),
            (String) matchRelationshipComboBox.getSelectedItem(),
            matchHighlighterTextField.getText()
        );
        newHighlighter.setEnabled(newHighlighter.isEnabled());
        highlighterTableModel.update(menuTable.getSelectedRow(), newHighlighter);
        highlighterTableModel.fireTableDataChanged();
      }
    });
    deleteHighlighterButton.addActionListener(l -> {
      highlighterTableModel.delete(menuTable.getSelectedRow());
      highlighterTableModel.fireTableDataChanged();
    });
    return outputPanel;
  }

  public JPanel createHighlightEditorUI() {
    booleanOperatorComboBox = new JComboBox<>(Highlighter.BOOLEAN_OPERATOR_OPTIONS);
    originalOrModifiedComboBox = new JComboBox<>(Highlighter.ORIGINAL_OR_MODIFIED);
    matchTypeComboBox = new JComboBox<>(Highlighter.MATCH_TYPE_OPTIONS);
    matchRelationshipComboBox = new JComboBox<>(
      Highlighter.getMatchRelationshipOptions(
        Highlighter.MATCH_TYPE_OPTIONS[0]));
    matchHighlighterTextField = new JTextField();

    booleanOperatorComboBox.setPreferredSize(AutoRepeater.comboBoxDimension);
    originalOrModifiedComboBox.setPreferredSize(AutoRepeater.comboBoxDimension);
    matchTypeComboBox.setPreferredSize(AutoRepeater.comboBoxDimension);
    matchRelationshipComboBox.setPreferredSize(AutoRepeater.comboBoxDimension);
    matchHighlighterTextField.setPreferredSize(AutoRepeater.textFieldDimension);

    matchTypeComboBox.addActionListener(e -> {
      matchRelationshipComboBox
          .setModel(new DefaultComboBoxModel<>(Highlighter.getMatchRelationshipOptions(
              (String) matchTypeComboBox.getSelectedItem())));
      matchHighlighterTextField.setEnabled(Highlighter.matchConditionIsEditable(
          (String) matchTypeComboBox.getSelectedItem()));
    });

    colorLabel = new JLabel("Highlight Color: ");
    booleanOperatorLabel = new JLabel("Boolean Operator: ");
    originalOrModifiedLabel = new JLabel("Match Original Or Modified");
    matchTypeLabel = new JLabel("Match Type: ");
    matchRelationshipLabel = new JLabel("Match Relationship: ");
    matchHighlighterLabel = new JLabel("Match Filter: ");

    JPanel outputPanel = new JPanel();
    outputPanel.setLayout(new GridBagLayout());
    GridBagConstraints c;
    c = new GridBagConstraints();

    c.gridx = 0;
    c.gridy = 0;
    c.anchor = GridBagConstraints.WEST;
    outputPanel.add(booleanOperatorLabel, c);
    c.gridy = 1;
    outputPanel.add(originalOrModifiedLabel, c);
    c.gridy = 2;
    outputPanel.add(matchTypeLabel, c);
    c.gridy = 3;
    outputPanel.add(matchRelationshipLabel, c);
    c.gridy = 4;
    outputPanel.add(matchHighlighterLabel, c);

    c.anchor = GridBagConstraints.EAST;
    c.fill = GridBagConstraints.HORIZONTAL;
    c.gridx = 1;
    c.gridy = 0;
    outputPanel.add(booleanOperatorComboBox, c);
    c.gridy = 1;
    outputPanel.add(originalOrModifiedComboBox, c);
    c.gridy = 2;
    outputPanel.add(matchTypeComboBox, c);
    c.gridy = 3;
    outputPanel.add(matchRelationshipComboBox, c);
    c.gridy = 4;
    outputPanel.add(matchHighlighterTextField, c);
    return outputPanel;
  }
}
