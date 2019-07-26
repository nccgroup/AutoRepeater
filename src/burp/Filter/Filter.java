package burp.Filter;

import burp.Conditions.Condition;
import burp.Logs.LogEntry;

public class Filter extends Condition {
  private String originalOrModified;
  public static final String[] ORIGINAL_OR_MODIFIED= {"Original", "Modified"};

  public Filter(
      String booleanOperator,
      String originalOrModified,
      String matchType,
      String matchRelationship,
      String matchCondition,
      boolean isEnabled) {
    super(booleanOperator, matchType, matchRelationship, matchCondition, isEnabled);
    setOriginalOrModified(originalOrModified);
  }

  public Filter(
      String booleanOperator,
      String originalOrModified,
      String matchType,
      String matchRelationship,
      String matchCondition) {
    this(booleanOperator, originalOrModified, matchType, matchRelationship, matchCondition, true);
  }

  public Filter(Filter filter) {
    this(filter.getBooleanOperator(),
        filter.getOriginalOrModified(),
        filter.getMatchType(),
        filter.getMatchRelationship(),
        filter.getMatchCondition(),
        filter.isEnabled());
    if(getBooleanOperator().equals("")) {
      setBooleanOperator("And");
    }
  }

  public boolean checkCondition(LogEntry logEntry) {
    if (getOriginalOrModified().equals("Original")) {
      return checkCondition(logEntry.getToolFlag(), logEntry.getOriginalRequestResponse());
    } else {
      return checkCondition(logEntry.getToolFlag(), logEntry.getModifiedRequestResponse());
    }
  }

  public String getOriginalOrModified() {
    return originalOrModified;
  }

  public void setOriginalOrModified(String originalOrModified) {
    if (originalOrModified.equals("Original")) {
      this.originalOrModified = "Original";
    } else {
      this.originalOrModified = "Modified";
    }
  }
}
