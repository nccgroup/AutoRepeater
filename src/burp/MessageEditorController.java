package burp;

public class MessageEditorController implements IMessageEditorController {

  private IHttpRequestResponse displayedItem;

  public IHttpRequestResponse getDisplayedItem() {
    return displayedItem;
  }

  public void setDisplayedItem(IHttpRequestResponse displayedItem) {
    this.displayedItem = displayedItem;
  }

  @Override
  public byte[] getRequest() {
    return displayedItem.getRequest();
  }

  @Override
  public byte[] getResponse() {
    return displayedItem.getResponse();
  }

  @Override
  public IHttpService getHttpService() {
    return displayedItem.getHttpService();
  }
}
