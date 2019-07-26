package burp.Filter;

import burp.AutoRepeater;
import burp.BurpExtender;
import burp.Logs.LogEntry;
import burp.Logs.LogManager;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import javax.swing.ButtonGroup;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;

public class Filters {

  // Filters UI
  private JPanel filtersPanel;
  private JPanel filterPanel;
  private JScrollPane filterScrollPane;
  private JRadioButton whitelistFilterRadioButton;
  private JRadioButton blacklistFilterRadioButton;
  private ButtonGroup buttonGroup;
  private JTable filterTable;
  private JButton addFilterButton;
  private JPanel filtersButtonPanel;
  private JButton editFilterButton;
  private JButton deleteFilterButton;
  private JButton duplicateFilterButton;

  // Filters Popup UI
  private JComboBox<String> booleanOperatorComboBox;
  private JComboBox<String> originalOrModifiedComboBox;
  private JComboBox<String> matchTypeComboBox;
  private JComboBox<String> matchRelationshipComboBox;
  private JTextField matchFilterTextField;

  private JLabel booleanOperatorLabel;
  private JLabel originalOrModifiedLabel;
  private JLabel matchTypeLabel;
  private JLabel matchRelationshipLabel;
  private JLabel matchFilterLabel;

  private FilterTableModel filterTableModel;
  private LogManager logManager;
  private boolean isWhitelist = true;

  public Filters(LogManager logManager) {
    filterTableModel = new FilterTableModel();
    this.logManager = logManager;
    createUI();
  }

  public FilterTableModel getFilterTableModel() { return filterTableModel; }
  public JPanel getUI() { return filtersPanel; }

  private void resetFilterDialog() {
    booleanOperatorComboBox.setSelectedIndex(0);
    originalOrModifiedComboBox.setSelectedIndex(0);
    matchTypeComboBox.setSelectedIndex(0);
    matchRelationshipComboBox.setSelectedIndex(0);
    matchFilterTextField.setText("");
  }

  public boolean filter(LogEntry logEntry) {
    if (isWhitelist) {
      return filterTableModel.check(logEntry);
    } else {
      return !filterTableModel.check(logEntry);
    }
  }

  public boolean isWhitelist() { return isWhitelist; }

  private void createUI() {
    GridBagConstraints c;
    //Filter Dialog
    c = new GridBagConstraints();
    filtersPanel = new JPanel();
    filterPanel = new JPanel();
    filterPanel.setLayout(new GridBagLayout());
    filterPanel.setPreferredSize(AutoRepeater.dialogDimension);

    whitelistFilterRadioButton = new JRadioButton("Whitelist");
    whitelistFilterRadioButton.setSelected(true);
    blacklistFilterRadioButton = new JRadioButton("Blacklist");
    buttonGroup = new ButtonGroup();
    buttonGroup.add(whitelistFilterRadioButton);
    buttonGroup.add(blacklistFilterRadioButton);

    booleanOperatorComboBox = new JComboBox<>(Filter.BOOLEAN_OPERATOR_OPTIONS);
    originalOrModifiedComboBox = new JComboBox<>(Filter.ORIGINAL_OR_MODIFIED);
    matchTypeComboBox = new JComboBox<>(Filter.MATCH_TYPE_OPTIONS);
    matchRelationshipComboBox = new JComboBox<>(Filter.getMatchRelationshipOptions(
        Filter.MATCH_TYPE_OPTIONS[0]));
    matchFilterTextField = new JTextField();

    booleanOperatorComboBox.setPreferredSize(AutoRepeater.comboBoxDimension);
    originalOrModifiedComboBox.setPreferredSize(AutoRepeater.comboBoxDimension);
    matchTypeComboBox.setPreferredSize(AutoRepeater.comboBoxDimension);
    matchRelationshipComboBox.setPreferredSize(AutoRepeater.comboBoxDimension);
    matchFilterTextField.setPreferredSize(AutoRepeater.textFieldDimension);

    matchTypeComboBox.addActionListener(e -> {
      matchRelationshipComboBox
          .setModel(new DefaultComboBoxModel<>(Filter.getMatchRelationshipOptions(
              (String) matchTypeComboBox.getSelectedItem())));
      matchFilterTextField.setEnabled(Filter.matchConditionIsEditable(
          (String) matchTypeComboBox.getSelectedItem()));
    });

    booleanOperatorLabel = new JLabel("Boolean Operator: ");
    originalOrModifiedLabel = new JLabel("Match Original Or Modified: ");
    matchTypeLabel = new JLabel("Match Type: ");
    matchRelationshipLabel = new JLabel("Match Relationship: ");
    matchFilterLabel = new JLabel("Match Condition: ");

    c.gridx = 0;
    c.gridy = 0;
    c.anchor = GridBagConstraints.WEST;
    filterPanel.add(booleanOperatorLabel, c);
    c.gridy = 1;
    filterPanel.add(originalOrModifiedLabel, c);
    c.gridy = 2;
    filterPanel.add(matchTypeLabel, c);
    c.gridy = 3;
    filterPanel.add(matchRelationshipLabel, c);
    c.gridy = 4;
    filterPanel.add(matchFilterLabel, c);

    c.anchor = GridBagConstraints.EAST;
    c.fill = GridBagConstraints.HORIZONTAL;
    c.gridx = 1;
    c.gridy = 0;
    filterPanel.add(booleanOperatorComboBox, c);
    c.gridy = 1;
    filterPanel.add(originalOrModifiedComboBox, c);
    c.gridy = 2;
    filterPanel.add(matchTypeComboBox, c);
    c.gridy = 3;
    filterPanel.add(matchRelationshipComboBox, c);
    c.gridy = 4;
    filterPanel.add(matchFilterTextField, c);

    // Filter Buttons
    addFilterButton = new JButton("Add");
    addFilterButton.setPreferredSize(AutoRepeater.buttonDimension);
    addFilterButton.setMinimumSize(AutoRepeater.buttonDimension);
    addFilterButton.setMaximumSize(AutoRepeater.buttonDimension);

    addFilterButton.addActionListener(e -> {
      int result = JOptionPane.showConfirmDialog(
          BurpExtender.getParentTabbedPane(),
          filterPanel,
          "Add Filter",
          JOptionPane.OK_CANCEL_OPTION,
          JOptionPane.PLAIN_MESSAGE);
      if (result == JOptionPane.OK_OPTION) {
        Filter newFilter = new Filter(
            (String) booleanOperatorComboBox.getSelectedItem(),
            (String) originalOrModifiedComboBox.getSelectedItem(),
            (String) matchTypeComboBox.getSelectedItem(),
            (String) matchRelationshipComboBox.getSelectedItem(),
            matchFilterTextField.getText()
        );
        filterTableModel.add(newFilter);
        filterTableModel.fireTableDataChanged();
      }
      resetFilterDialog();
    });

    editFilterButton = new JButton("Edit");
    editFilterButton.setPreferredSize(AutoRepeater.buttonDimension);
    editFilterButton.setMinimumSize(AutoRepeater.buttonDimension);
    editFilterButton.setMaximumSize(AutoRepeater.buttonDimension);

    editFilterButton.addActionListener(e -> {
      int selectedRow = filterTable.getSelectedRow();
      if (selectedRow != -1) {
        Filter tempFilter = filterTableModel.get(selectedRow);

        booleanOperatorComboBox.setSelectedItem(tempFilter.getBooleanOperator());
        originalOrModifiedComboBox.setSelectedItem(tempFilter.getOriginalOrModified());
        matchTypeComboBox.setSelectedItem(tempFilter.getMatchType());
        matchRelationshipComboBox.setSelectedItem(tempFilter.getMatchRelationship());
        matchFilterTextField.setText(tempFilter.getMatchCondition());

        int result = JOptionPane.showConfirmDialog(
            BurpExtender.getParentTabbedPane(),
            filterPanel,
            "Edit Filter",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
          Filter newFilter = new Filter(
              (String) booleanOperatorComboBox.getSelectedItem(),
              (String) originalOrModifiedComboBox.getSelectedItem(),
              (String) matchTypeComboBox.getSelectedItem(),
              (String) matchRelationshipComboBox.getSelectedItem(),
              matchFilterTextField.getText()
          );
          newFilter.setEnabled(tempFilter.isEnabled());

          filterTableModel.update(selectedRow, newFilter);
          filterTableModel.fireTableDataChanged();
        }
        resetFilterDialog();
      }
    });

    deleteFilterButton = new JButton("Remove");
    deleteFilterButton.setPreferredSize(AutoRepeater.buttonDimension);
    deleteFilterButton.setMinimumSize(AutoRepeater.buttonDimension);
    deleteFilterButton.setMaximumSize(AutoRepeater.buttonDimension);

    deleteFilterButton.addActionListener(e -> {
      int selectedRow = filterTable.getSelectedRow();
      if (selectedRow != -1) {
        filterTableModel.remove(selectedRow);
        filterTableModel.fireTableDataChanged();
      }
    });

    filtersButtonPanel = new JPanel();
    filtersButtonPanel.setLayout(new GridBagLayout());

    duplicateFilterButton = new JButton("Duplicate");
    duplicateFilterButton.setPreferredSize(AutoRepeater.buttonDimension);
    duplicateFilterButton.setMinimumSize(AutoRepeater.buttonDimension);
    duplicateFilterButton.setMaximumSize(AutoRepeater.buttonDimension);

    duplicateFilterButton.addActionListener(e -> {
      int selectedRow = filterTable.getSelectedRow();
      if (selectedRow != -1 && selectedRow < filterTableModel.getConditions().size()) {
        filterTableModel.add(new Filter(filterTableModel.getFilters().get(selectedRow)));
        filterTableModel.fireTableDataChanged();
      }
    });

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_START;
    c.gridx = 0;
    c.weightx = 1;

    filtersButtonPanel.add(addFilterButton, c);
    filtersButtonPanel.add(editFilterButton, c);
    filtersButtonPanel.add(deleteFilterButton, c);
    filtersButtonPanel.add(duplicateFilterButton, c);
    filtersButtonPanel.add(whitelistFilterRadioButton, c);
    filtersButtonPanel.add(blacklistFilterRadioButton, c);

    filterTableModel = new FilterTableModel();
    filterTable = new JTable(filterTableModel);
    filterTable.getColumnModel().getColumn(0).setMinWidth(55);
    filterTable.getColumnModel().getColumn(0).setMaxWidth(55);

    filterTable.setPreferredSize(AutoRepeater.tableDimension);
    filterTable.setMaximumSize(AutoRepeater.tableDimension);
    filterTable.setMinimumSize(AutoRepeater.tableDimension);

    filterScrollPane = new JScrollPane(filterTable);

    // Panel containing filter options
    filtersPanel.setLayout(new GridBagLayout());
    c = new GridBagConstraints();
    c.ipady = 0;
    c.anchor = GridBagConstraints.PAGE_START;
    c.gridx = 0;
    filtersPanel.add(filtersButtonPanel, c);
    c.fill = GridBagConstraints.BOTH;
    c.weightx = 1;
    c.weighty = 1;
    c.gridx = 1;
    filtersPanel.add(filterScrollPane, c);
    // Refilter the logs whenever anything is touched. For whatever reason click the enabled

    whitelistFilterRadioButton.addActionListener(e -> {
      setWhitelist(whitelistFilterRadioButton.isSelected());
      logManager.setFilter(this);
    });
    blacklistFilterRadioButton.addActionListener(e -> {
      setWhitelist(!blacklistFilterRadioButton.isSelected());
      logManager.setFilter(this);
    });
    filterTableModel.addTableModelListener(e -> logManager.setFilter(this));
  }

  public void setWhitelist(boolean whitelist) {
    isWhitelist = whitelist;
    if(isWhitelist) {
      whitelistFilterRadioButton.setSelected(true);
    } else {
      blacklistFilterRadioButton.setSelected(true);
    }
  }
}
