package burp.Conditions;

import burp.AutoRepeater;
import burp.BurpExtender;
import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;

public class Conditions {
  // Conditions UI
  JPanel conditionsPanel;
  private JPanel conditionPanel;
  private JScrollPane conditionScrollPane;
  private JTable conditionTable;
  private JPanel conditionsButtonPanel;
  private JButton addConditionButton;
  private JButton editConditionButton;
  private JButton deleteConditionButton;
  private JButton duplicateConditionButton;

  // Conditions Popup UI
  private JComboBox<String> booleanOperatorComboBox;
  private JComboBox<String> matchTypeComboBox;
  private JComboBox<String> matchRelationshipComboBox;
  private JTextField matchConditionTextField;

  private JLabel booleanOperatorLabel;
  private JLabel matchTypeLabel;
  private JLabel matchRelationshipLabel;
  private JLabel matchConditionLabel;

  private ConditionTableModel conditionTableModel;

  public Conditions() {
    conditionTableModel = new ConditionTableModel();
    createUI();
  }

  public ConditionTableModel getConditionTableModel() { return conditionTableModel; }
  public JPanel getUI() { return conditionsPanel; }

  private void resetConditionDialog() {
    booleanOperatorComboBox.setSelectedIndex(0);
    matchTypeComboBox.setSelectedIndex(0);
    matchRelationshipComboBox.setSelectedIndex(0);
    matchConditionTextField.setText("");
  }

  private void createUI() {
    GridBagConstraints c;
    //Condition Dialog
    c = new GridBagConstraints();
    conditionsPanel = new JPanel();
    conditionPanel = new JPanel();
    conditionPanel.setLayout(new GridBagLayout());
    conditionPanel.setPreferredSize(AutoRepeater.dialogDimension);

    booleanOperatorComboBox = new JComboBox<>(Condition.BOOLEAN_OPERATOR_OPTIONS);
    matchTypeComboBox = new JComboBox<>(Condition.MATCH_TYPE_OPTIONS);
    matchRelationshipComboBox = new JComboBox<>(Condition.getMatchRelationshipOptions(
        Condition.MATCH_TYPE_OPTIONS[0]));
    matchConditionTextField = new JTextField();

    booleanOperatorComboBox.setPreferredSize(AutoRepeater.comboBoxDimension);
    matchTypeComboBox.setPreferredSize(AutoRepeater.comboBoxDimension);
    matchRelationshipComboBox.setPreferredSize(AutoRepeater.comboBoxDimension);
    matchConditionTextField.setPreferredSize(AutoRepeater.textFieldDimension);

    matchTypeComboBox.addActionListener(e -> {
      matchRelationshipComboBox
          .setModel(new DefaultComboBoxModel<>(Condition.getMatchRelationshipOptions(
              (String) matchTypeComboBox.getSelectedItem())));
      matchConditionTextField.setEnabled(Condition.matchConditionIsEditable(
          (String) matchTypeComboBox.getSelectedItem()));
    });

    booleanOperatorLabel = new JLabel("Boolean Operator: ");
    matchTypeLabel = new JLabel("Match Type: ");
    matchRelationshipLabel = new JLabel("Match Relationship: ");
    matchConditionLabel = new JLabel("Match Condition: ");

    c.gridx = 0;
    c.gridy = 0;
    c.anchor = GridBagConstraints.WEST;
    conditionPanel.add(booleanOperatorLabel, c);
    c.gridy = 1;
    conditionPanel.add(matchTypeLabel, c);
    c.gridy = 2;
    conditionPanel.add(matchRelationshipLabel, c);
    c.gridy = 3;
    conditionPanel.add(matchConditionLabel, c);

    c.anchor = GridBagConstraints.EAST;
    c.fill = GridBagConstraints.HORIZONTAL;
    c.gridx = 1;
    c.gridy = 0;
    conditionPanel.add(booleanOperatorComboBox, c);
    c.gridy = 1;
    conditionPanel.add(matchTypeComboBox, c);
    c.gridy = 2;
    conditionPanel.add(matchRelationshipComboBox, c);
    c.gridy = 3;
    conditionPanel.add(matchConditionTextField, c);

    // Condition Buttons
    addConditionButton = new JButton("Add");
    addConditionButton.setPreferredSize(AutoRepeater.buttonDimension);
    addConditionButton.setMinimumSize(AutoRepeater.buttonDimension);
    addConditionButton.setMaximumSize(AutoRepeater.buttonDimension);

    addConditionButton.addActionListener(e -> {
      int result = JOptionPane.showConfirmDialog(
          BurpExtender.getParentTabbedPane(),
          conditionPanel,
          "Add Condition",
          JOptionPane.OK_CANCEL_OPTION,
          JOptionPane.PLAIN_MESSAGE);
      if (result == JOptionPane.OK_OPTION) {
        Condition newCondition = new Condition(
            (String) booleanOperatorComboBox.getSelectedItem(),
            (String) matchTypeComboBox.getSelectedItem(),
            (String) matchRelationshipComboBox.getSelectedItem(),
            matchConditionTextField.getText()
        );
        conditionTableModel.add(newCondition);
        conditionTableModel.fireTableDataChanged();
      }
      resetConditionDialog();
    });

    editConditionButton = new JButton("Edit");
    editConditionButton.setPreferredSize(AutoRepeater.buttonDimension);
    editConditionButton.setMinimumSize(AutoRepeater.buttonDimension);
    editConditionButton.setMaximumSize(AutoRepeater.buttonDimension);

    editConditionButton.addActionListener(e -> {
      if (conditionTable.getSelectedRow() != -1) {
        int selectedRow = conditionTable.getSelectedRow();
        Condition tempCondition = conditionTableModel.get(selectedRow);

        booleanOperatorComboBox.setSelectedItem(tempCondition.getBooleanOperator());
        matchTypeComboBox.setSelectedItem(tempCondition.getMatchType());
        matchRelationshipComboBox.setSelectedItem(tempCondition.getMatchRelationship());
        matchConditionTextField.setText(tempCondition.getMatchCondition());

        int result = JOptionPane.showConfirmDialog(
            BurpExtender.getParentTabbedPane(),
            conditionPanel,
            "Edit Condition",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
          Condition newCondition = new Condition(
              (String) booleanOperatorComboBox.getSelectedItem(),
              (String) matchTypeComboBox.getSelectedItem(),
              (String) matchRelationshipComboBox.getSelectedItem(),
              matchConditionTextField.getText()
          );
          newCondition.setEnabled(tempCondition.isEnabled());
          conditionTableModel.update(selectedRow, newCondition);
          conditionTableModel.fireTableDataChanged();
        }
        resetConditionDialog();
      }
    });

    deleteConditionButton = new JButton("Remove");
    deleteConditionButton.setPreferredSize(AutoRepeater.buttonDimension);
    deleteConditionButton.setMinimumSize(AutoRepeater.buttonDimension);
    deleteConditionButton.setMaximumSize(AutoRepeater.buttonDimension);

    deleteConditionButton.addActionListener(e -> {
      int selectedRow = conditionTable.getSelectedRow();
      if (selectedRow != -1) {
        conditionTableModel.remove(selectedRow);
        conditionTableModel.fireTableDataChanged();
      }
    });


    // Duplicate Condition
    duplicateConditionButton = new JButton("Duplicate");
    duplicateConditionButton.setPreferredSize(AutoRepeater.buttonDimension);
    duplicateConditionButton.setMinimumSize(AutoRepeater.buttonDimension);
    duplicateConditionButton.setMaximumSize(AutoRepeater.buttonDimension);

    duplicateConditionButton.addActionListener(e -> {
      int selectedRow = conditionTable.getSelectedRow();
      if (conditionTable.getSelectedRow() != -1
          && selectedRow < getConditionTableModel().getConditions().size()) {
        conditionTableModel.add(new Condition(getConditionTableModel().get(selectedRow)));
        conditionTableModel.fireTableDataChanged();
      }
    });

    conditionsButtonPanel = new JPanel();
    conditionsButtonPanel.setLayout(new GridBagLayout());
    conditionsButtonPanel.setPreferredSize(AutoRepeater.buttonPanelDimension);
    conditionsButtonPanel.setMaximumSize(AutoRepeater.buttonPanelDimension);
    conditionsButtonPanel.setPreferredSize(AutoRepeater.buttonPanelDimension);

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_END;
    c.gridx = 0;
    c.weightx = 1;

    conditionsButtonPanel.add(addConditionButton, c);
    conditionsButtonPanel.add(editConditionButton, c);
    conditionsButtonPanel.add(deleteConditionButton, c);
    conditionsButtonPanel.add(duplicateConditionButton, c);

    conditionTableModel = new ConditionTableModel();
    conditionTable = new JTable(conditionTableModel);
    conditionTable.getColumnModel().getColumn(0).setMaxWidth(55);
    conditionTable.getColumnModel().getColumn(0).setMinWidth(55);
    conditionScrollPane = new JScrollPane(conditionTable);

    // Panel containing condition options
    conditionsPanel.setLayout(new GridBagLayout());
    c = new GridBagConstraints();
    c.ipady = 0;
    c.anchor = GridBagConstraints.PAGE_START;
    c.gridx = 0;
    conditionsPanel.add(conditionsButtonPanel, c);
    c.fill = GridBagConstraints.BOTH;
    c.weightx = 1;
    c.weighty = 1;
    c.gridx = 1;
    conditionsPanel.add(conditionScrollPane, c);
  }
}
