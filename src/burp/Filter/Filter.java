package burp.Filter;

//TODO: Notes for implementation.
// Each tab will has a list of filters.
// There will be three types of filters: whitelist, blacklist, and highlight
// Each filter will be a set of and/or checks based on conditions

import burp.Conditions.Condition;

public class Filter extends Condition {

  public Filter(
      String booleanOperator,
      String matchType,
      String matchRelationship,
      String matchCondition) {
    super(booleanOperator, matchType, matchRelationship, matchCondition);
  }

  public Filter(
      String booleanOperator,
      String matchType,
      String matchRelationship,
      String matchCondition,
      boolean isEnabled) {
    super(booleanOperator, matchType, matchRelationship, matchCondition, isEnabled);
  }
}
