package burp.Replacements;

import burp.AutoRepeater;
import burp.BurpExtender;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;

public class Replacements {

  // Replacements UI
  private JPanel replacementsPanel;
  private JScrollPane replacementScrollPane;
  private JTable replacementTable;
  private JButton addReplacementButton;
  private JPanel replacementsButtonPanel;
  private JButton editReplacementButton;
  private JButton deleteReplacementButton;
  private JButton duplicateReplacementButton;

  // Replacements popup UI
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

  // Replacements Data Store
  private ReplacementTableModel replacementTableModel;

  public Replacements() {
    replacementTableModel = new ReplacementTableModel();
    createUI();
  }

  public ReplacementTableModel getReplacementTableModel() { return replacementTableModel; }
  public JPanel getUI() { return replacementsPanel; }

  private void createUI() {
    GridBagConstraints c;
    replacementPanel = new JPanel();
    replacementPanel.setLayout(new GridBagLayout());
    replacementPanel.setPreferredSize(AutoRepeater.dialogDimension);

    c = new GridBagConstraints();

    replacementTypeComboBox = new JComboBox<>(Replacement.REPLACEMENT_TYPE_OPTIONS);
    replacementCountComboBox = new JComboBox<>(Replacement.REPLACEMENT_COUNT_OPTINONS);
    replacementMatchTextField = new JTextField();
    replacementReplaceTextField = new JTextField();
    replacementCommentTextField = new JTextField();
    replacementIsRegexCheckBox = new JCheckBox();

    replacementTypeComboBox.setPreferredSize(AutoRepeater.comboBoxDimension);
    replacementCountComboBox.setPreferredSize(AutoRepeater.comboBoxDimension);
    replacementMatchTextField.setPreferredSize(AutoRepeater.textFieldDimension);
    replacementReplaceTextField.setPreferredSize(AutoRepeater.textFieldDimension);
    replacementCommentTextField.setPreferredSize(AutoRepeater.textFieldDimension);

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

    // Replacement Buttons
    addReplacementButton = new JButton("Add");
    addReplacementButton.setPreferredSize(AutoRepeater.buttonDimension);
    addReplacementButton.setMinimumSize(AutoRepeater.buttonDimension);
    addReplacementButton.setMaximumSize(AutoRepeater.buttonDimension);

    // Add New Replacement
    addReplacementButton.addActionListener(e -> {
      int result = JOptionPane.showConfirmDialog(
          BurpExtender.getParentTabbedPane(),
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
    editReplacementButton.setPreferredSize(AutoRepeater.buttonDimension);
    editReplacementButton.setMinimumSize(AutoRepeater.buttonDimension);
    editReplacementButton.setMaximumSize(AutoRepeater.buttonDimension);

    // Edit selected Replacement
    editReplacementButton.addActionListener(e -> {
      int selectedRow = replacementTable.getSelectedRow();
      if (selectedRow != -1) {
        Replacement tempReplacement = replacementTableModel.getReplacement(selectedRow);

        replacementTypeComboBox.setSelectedItem(tempReplacement.getType());
        replacementMatchTextField.setText(tempReplacement.getMatch());
        replacementReplaceTextField.setText(tempReplacement.getReplace());
        replacementCountComboBox.setSelectedItem(tempReplacement.getWhich());
        replacementCommentTextField.setText(tempReplacement.getComment());
        replacementIsRegexCheckBox.setSelected(tempReplacement.isRegexMatch());

        int result = JOptionPane.showConfirmDialog(
            BurpExtender.getParentTabbedPane(),
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
      }
    });

    deleteReplacementButton = new JButton("Remove");
    deleteReplacementButton.setPreferredSize(AutoRepeater.buttonDimension);
    deleteReplacementButton.setMinimumSize(AutoRepeater.buttonDimension);
    deleteReplacementButton.setMaximumSize(AutoRepeater.buttonDimension);

    //Delete Replacement
    deleteReplacementButton.addActionListener(e -> {
      int selectedRow = replacementTable.getSelectedRow();
      if (selectedRow != -1) {
        replacementTableModel.deleteReplacement(selectedRow);
        replacementTableModel.fireTableDataChanged();
      }
    });

    duplicateReplacementButton = new JButton("Duplicate");
    duplicateReplacementButton.setPreferredSize(AutoRepeater.buttonDimension);
    duplicateReplacementButton.setMinimumSize(AutoRepeater.buttonDimension);
    duplicateReplacementButton.setMaximumSize(AutoRepeater.buttonDimension);

    // Duplicate a replacement
    duplicateReplacementButton.addActionListener(e -> {
      int selectedRow = replacementTable.getSelectedRow();
      if (selectedRow != -1 && selectedRow < replacementTableModel.getReplacements().size()) {
        replacementTableModel.addReplacement(
            new Replacement(replacementTableModel.getReplacement(selectedRow)));
        replacementTableModel.fireTableDataChanged();
      }
    });

    replacementsButtonPanel = new JPanel();
    replacementsButtonPanel.setLayout(new GridBagLayout());
    replacementsButtonPanel.setPreferredSize(AutoRepeater.buttonPanelDimension);

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_END;
    c.gridx = 0;
    c.weightx = 1;

    replacementsButtonPanel.add(addReplacementButton, c);
    replacementsButtonPanel.add(editReplacementButton, c);
    replacementsButtonPanel.add(deleteReplacementButton, c);
    replacementsButtonPanel.add(duplicateReplacementButton, c);

    replacementTableModel = new ReplacementTableModel();
    replacementTable = new JTable(replacementTableModel);
    replacementTable.getColumnModel().getColumn(0).setMaxWidth(55);
    replacementTable.getColumnModel().getColumn(0).setMinWidth(55);
    replacementScrollPane = new JScrollPane(replacementTable);
    replacementScrollPane.setMinimumSize(AutoRepeater.tableDimension);

    // Panel containing replacement options
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
  }

  private void resetReplacementDialog() {
    replacementTypeComboBox.setSelectedIndex(0);
    replacementCountComboBox.setSelectedIndex(0);
    replacementMatchTextField.setText("");
    replacementReplaceTextField.setText("");
    replacementCommentTextField.setText("");
    replacementIsRegexCheckBox.setSelected(false);
  }

}
