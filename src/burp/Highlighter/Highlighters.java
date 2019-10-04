package burp.Highlighter;

import burp.AutoRepeater;
import burp.AutoRepeater.LogTable;
import burp.BurpExtender;
import burp.Logs.LogEntry;
import burp.Logs.LogManager;
import java.awt.Component;
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
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;

public class Highlighters {
  // Highlighters UI
  private JPanel highlightsPanel;

  // Highlighters Popup UI
  private JComboBox<String> booleanOperatorComboBox;
  private JComboBox<String> originalOrModifiedComboBox;
  private JComboBox<String> matchTypeComboBox;
  private JComboBox<String> matchRelationshipComboBox;
  private JTextField matchHighlighterTextField;

  // Highlighters Menu UI
  private JLabel booleanOperatorLabel;
  private JLabel originalOrModifiedLabel;
  private JLabel matchTypeLabel;
  private JLabel matchRelationshipLabel;
  private JLabel matchHighlighterLabel;
  private JTable highlighterTable;

  private HighlighterUITableModel highlighterUITableModel;
  private LogManager logManager;
  private LogTable logTable;

  public Highlighters(LogManager logManager, LogTable logTable) {
    highlighterUITableModel = new HighlighterUITableModel();
    highlighterUITableModel.addTableModelListener(l -> highlight());
    this.logManager = logManager;
    this.logTable = logTable;
    highlightsPanel = createMenuUI();
  }

  public HighlighterUITableModel getHighlighterUITableModel() { return highlighterUITableModel; }
  public JPanel getUI() { return highlightsPanel; }

  public void highlight() {
    for (LogEntry logEntry : logManager.getLogTableModel().getLog()) {
      highlight(logEntry);
    }
    logTable.repaint();
  }

  public void highlight(LogEntry logEntry) {
    logEntry.setBackgroundColor(Highlighter.COLORS[0], Highlighter.SELECTED_COLORS[0]);
    for (HighlighterTableModel highlighterTableModel : highlighterUITableModel.getTableModels()) {
      //if (highlighterTableModel.isEnabled()) {
        //for (Highlighter highlighter : highlighterTableModel.getHighlighters()) {
        if (highlighterTableModel.check(logEntry)) {
          logEntry.setBackgroundColor(
              highlighterTableModel.getColor(), highlighterTableModel.getSelectedColor());
        }
        //}
      //}
    }
    logTable.repaint();
  }

  private JPanel createMenuUI() {
    GridBagConstraints c;
    JPanel menuPanel = new JPanel();
    JButton addHighlighterButton = new JButton("Add");
    JButton editHighlighterButton = new JButton("Edit");
    JButton deleteHighlighterButton = new JButton("Remove");
    JButton duplicateHighlighterButton = new JButton("Duplicate");
    JPanel buttonsPanel = new JPanel();
    JTable menuTable = new JTable(highlighterUITableModel);

    menuTable.getColumnModel().getColumn(0).setMaxWidth(55);
    menuTable.getColumnModel().getColumn(0).setMinWidth(55);
    menuTable.getColumnModel().getColumn(1).setMaxWidth(70);
    menuTable.getColumnModel().getColumn(1).setMinWidth(70);
    //menuTable.getColumnModel().getColumn(2).setPreferredWidth(20);

    menuTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
      @Override
      public Component getTableCellRendererComponent(
          JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        Component c =
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        // Only color the color column
        if (column == 1) {
          c.setBackground(highlighterUITableModel.getTableModels().get(row).getColor());
          if (isSelected) {
            c.setBackground(highlighterUITableModel.getTableModels().get(row).getSelectedColor());
          }
        } else {
          c.setBackground(Highlighter.COLORS[0]);
          if (isSelected) {
            c.setBackground(Highlighter.SELECTED_COLORS[0]);
          }
        }
        return c;
      }
    });

    addHighlighterButton.setPreferredSize(AutoRepeater.buttonDimension);
    editHighlighterButton.setPreferredSize(AutoRepeater.buttonDimension);
    deleteHighlighterButton.setPreferredSize(AutoRepeater.buttonDimension);
    duplicateHighlighterButton.setPreferredSize(AutoRepeater.buttonDimension);

    addHighlighterButton.setMinimumSize(AutoRepeater.buttonDimension);
    editHighlighterButton.setMinimumSize(AutoRepeater.buttonDimension);
    deleteHighlighterButton.setMinimumSize(AutoRepeater.buttonDimension);
    duplicateHighlighterButton.setMinimumSize(AutoRepeater.buttonDimension);

    addHighlighterButton.setMaximumSize(AutoRepeater.buttonDimension);
    editHighlighterButton.setMaximumSize(AutoRepeater.buttonDimension);
    deleteHighlighterButton.setMaximumSize(AutoRepeater.buttonDimension);
    duplicateHighlighterButton.setMaximumSize(AutoRepeater.buttonDimension);

    buttonsPanel.setPreferredSize(AutoRepeater.buttonPanelDimension);

    buttonsPanel.setLayout(new GridBagLayout());
    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_START;
    c.gridx = 0;
    c.weightx = 0;
    buttonsPanel.add(addHighlighterButton, c);
    buttonsPanel.add(editHighlighterButton, c);
    buttonsPanel.add(deleteHighlighterButton, c);
    buttonsPanel.add(duplicateHighlighterButton, c);

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
      HighlighterTableModel tableModel = new HighlighterTableModel();
      tableModel.addTableModelListener(e -> highlight());
      int result = JOptionPane.showConfirmDialog(
          BurpExtender.getParentTabbedPane(),
          createHighlighterUI(tableModel),
          "Add Highlighter",
          JOptionPane.OK_CANCEL_OPTION,
          JOptionPane.PLAIN_MESSAGE);
      if (result == JOptionPane.OK_OPTION) {
        HighlighterTableModel tempTableModel = new HighlighterTableModel(tableModel);
        if(tempTableModel.getConditions().size() > 0) {
          tempTableModel.setEnabled(true);
          highlighterUITableModel.add(tempTableModel);
          highlight();
          highlighterUITableModel.fireTableDataChanged();
        }
      }
    });
    editHighlighterButton.addActionListener(l -> {
      if (menuTable.getSelectedRow() != -1) {
        HighlighterTableModel tableModel = highlighterUITableModel.get(menuTable.getSelectedRow());
        tableModel.addTableModelListener(e -> highlight());
        int result = JOptionPane.showConfirmDialog(
            BurpExtender.getParentTabbedPane(),
            createHighlighterUI(tableModel),
            "Add Highlighter",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
          HighlighterTableModel tempTableModel = new HighlighterTableModel(tableModel);
          if (tempTableModel.getConditions().size() > 0) {
            highlighterUITableModel.update(menuTable.getSelectedRow(), tempTableModel);
            highlight();
            highlighterUITableModel.fireTableDataChanged();
          }
        }
      }
    });
    deleteHighlighterButton.addActionListener(l -> {
      if (menuTable.getSelectedRow() != -1) {
        highlighterUITableModel.remove(menuTable.getSelectedRow());
        highlight();
        highlighterUITableModel.fireTableDataChanged();
      }
    });
    duplicateHighlighterButton.addActionListener(l -> {
      int selectedRow = menuTable.getSelectedRow();
      if (selectedRow != -1 && selectedRow < highlighterUITableModel.getRowCount()) {
        highlighterUITableModel.add(new HighlighterTableModel(highlighterUITableModel.get(selectedRow)));
        highlighterUITableModel.fireTableDataChanged();
      }
    });
    return menuPanel;
  }

  // This is the UI for the highlighter pop up with the table
  private JPanel createHighlighterUI(HighlighterTableModel highlighterTableModel) {
    GridBagConstraints c;
    JPanel menuPanel = new JPanel();
    JButton addHighlighterButton = new JButton("Add");
    JButton editHighlighterButton = new JButton("Edit");
    JButton deleteHighlighterButton = new JButton("Remove");
    JButton duplicateHighlighterButton = new JButton("Duplicate");
    JPanel buttonsPanel = new JPanel();
    JTextField commentTextField = new JTextField();
    commentTextField.setText(highlighterTableModel.getComment());
    JLabel commentTextFieldLabel = new JLabel("Comment: ");

    commentTextField.getDocument().addDocumentListener(new DocumentListener() {
       @Override
       public void insertUpdate(DocumentEvent e) {
         highlighterTableModel.setComment(commentTextField.getText());
       }
       @Override
       public void removeUpdate(DocumentEvent e) {
         highlighterTableModel.setComment(commentTextField.getText());
       }
       @Override
       public void changedUpdate(DocumentEvent e) {
         highlighterTableModel.setComment(commentTextField.getText());
       }
     }
    );

    commentTextFieldLabel.setMaximumSize(AutoRepeater.buttonDimension);
    commentTextFieldLabel.setMinimumSize(AutoRepeater.buttonDimension);
    commentTextFieldLabel.setPreferredSize(AutoRepeater.buttonDimension);

    highlighterTable = new JTable(highlighterTableModel);
    highlighterTable.getColumnModel().getColumn(0).setMaxWidth(55);
    highlighterTable.getColumnModel().getColumn(0).setMinWidth(55);

    JLabel colorComboBoxLabel = new JLabel("Highlight Color: ");
    JComboBox<String> colorComboBox = new JComboBox<>(Highlighter.COLOR_NAMES);
    colorComboBox.setSelectedItem(highlighterTableModel.getColorName());
    colorComboBox.addActionListener(e ->
        highlighterTableModel.setColorName((String)colorComboBox.getSelectedItem()));
    colorComboBox.setRenderer((list, value, index, isSelected, cellHasFocus) -> {
      DefaultListCellRenderer defaultListCellRenderer = new DefaultListCellRenderer();
      JLabel label =
          (JLabel) defaultListCellRenderer
              .getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
      label.setOpaque(true);
      for (int i = 0; i < Highlighter.COLOR_NAMES.length; i++) {
        if (label.getText().equals(Highlighter.COLOR_NAMES[i])) {
          label.setBackground(Highlighter.COLORS[i]);
        }
      }
      return label;
    });
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
    addHighlighterButton.setMinimumSize(AutoRepeater.buttonDimension);
    addHighlighterButton.setMaximumSize(AutoRepeater.buttonDimension);

    editHighlighterButton.setPreferredSize(AutoRepeater.buttonDimension);
    editHighlighterButton.setMinimumSize(AutoRepeater.buttonDimension);
    editHighlighterButton.setMaximumSize(AutoRepeater.buttonDimension);

    deleteHighlighterButton.setPreferredSize(AutoRepeater.buttonDimension);
    deleteHighlighterButton.setMinimumSize(AutoRepeater.buttonDimension);
    deleteHighlighterButton.setMaximumSize(AutoRepeater.buttonDimension);

    duplicateHighlighterButton.setPreferredSize(AutoRepeater.buttonDimension);
    duplicateHighlighterButton.setMinimumSize(AutoRepeater.buttonDimension);
    duplicateHighlighterButton.setMaximumSize(AutoRepeater.buttonDimension);

    buttonsPanel.setPreferredSize(AutoRepeater.buttonPanelDimension);

    buttonsPanel.setLayout(new GridBagLayout());
    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_START;
    c.gridx = 0;
    c.weightx = 0;
    buttonsPanel.add(addHighlighterButton, c);
    buttonsPanel.add(editHighlighterButton, c);
    buttonsPanel.add(deleteHighlighterButton, c);
    buttonsPanel.add(duplicateHighlighterButton, c);

    JScrollPane menuScrollPane = new JScrollPane(highlighterTable);

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
    JPanel commentPanel = new JPanel();
    commentPanel.setLayout(new BoxLayout(commentPanel, BoxLayout.LINE_AXIS));
    commentPanel.add(commentTextFieldLabel);
    commentPanel.add(commentTextField);
    outputPanel.add(commentPanel);

    // Button Actions
    addHighlighterButton.addActionListener(l -> {
      int result = JOptionPane.showConfirmDialog(
          BurpExtender.getParentTabbedPane(),
          createHighlightEditorUI(highlighterTableModel),
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
      resetHighlighterDialog();
    });
    editHighlighterButton.addActionListener(l -> {
      if (highlighterTable.getSelectedRow() != -1) {
        int result = JOptionPane.showConfirmDialog(
            BurpExtender.getParentTabbedPane(),
            createHighlightEditorUI(highlighterTableModel),
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
          highlighterTableModel.update(highlighterTable.getSelectedRow(), newHighlighter);
          highlighterTableModel.fireTableDataChanged();
        }
      }
      resetHighlighterDialog();
    });
    deleteHighlighterButton.addActionListener(l -> {
      if (highlighterTable.getSelectedRow() != -1 ) {
        highlighterTableModel.remove(highlighterTable.getSelectedRow());
        highlighterTableModel.fireTableDataChanged();
      }
    });
    duplicateHighlighterButton.addActionListener(l -> {
      int selectedRow = highlighterTable.getSelectedRow();
      if (selectedRow != -1 && selectedRow < highlighterTableModel.getHighlighters().size()) {
        highlighterTableModel.add(
            new Highlighter(
                highlighterTableModel.getHighlighters().get(highlighterTable.getSelectedRow())));
        highlighterTableModel.fireTableDataChanged();
      }
    });
    return outputPanel;
  }

  private void resetHighlighterDialog() {
    booleanOperatorComboBox.setSelectedIndex(0);
    originalOrModifiedComboBox.setSelectedIndex(0);
    matchTypeComboBox.setSelectedIndex(0);
    matchRelationshipComboBox.setSelectedItem(0);
    matchHighlighterTextField.setText("");
  }

  public JPanel createHighlightEditorUI(HighlighterTableModel highlighterTableModel) {
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

    if (highlighterTable.getSelectedRow() != -1) {
      Highlighter tempHighlighter = highlighterTableModel.getHighlighters()
          .get(highlighterTable.getSelectedRow());
      booleanOperatorComboBox.setSelectedItem(tempHighlighter.getBooleanOperator());
      originalOrModifiedComboBox.setSelectedItem(tempHighlighter.getOriginalOrModified());
      matchTypeComboBox.setSelectedItem(tempHighlighter.getMatchType());
      matchRelationshipComboBox.setSelectedItem(tempHighlighter.getMatchRelationship());
      matchHighlighterTextField.setText(tempHighlighter.getMatchCondition());
    }

    booleanOperatorLabel = new JLabel("Boolean Operator: ");
    originalOrModifiedLabel = new JLabel("Match Original Or Modified: ");
    matchTypeLabel = new JLabel("Match Type: ");
    matchRelationshipLabel = new JLabel("Match Relationship: ");
    matchHighlighterLabel = new JLabel("Match Condition: ");

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
