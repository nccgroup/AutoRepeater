package burp;

/**
 * Created by j on 8/7/17.
 */


import com.google.gson.*;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import javax.swing.*;
import javax.swing.Timer;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory {

  // burp stuff
  private static IBurpExtenderCallbacks callbacks;
  private static IExtensionHelpers helpers;
  private static Gson gson;
  private static JTabbedPane mainTabbedPane;
  private static JTabbedPane parentTabbedPane;
  private ArrayList<AutoRepeater> autoRepeaters;
  private JPanel newTabButton;
  private int tabCounter = 0;
  private boolean tabChangeListenerLock = false;

  @Override
  public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
    // keep a reference to our callbacks object
    BurpExtender.callbacks = callbacks;
    // obtain an extension helpers object
    BurpExtender.helpers = callbacks.getHelpers();
    // Gson for serialization
    BurpExtender.gson = new Gson();
    //BurpExtender.gson = new GsonBuilder().setPrettyPrinting().create();
    autoRepeaters = new ArrayList<>();

    // create our UI
    SwingUtilities.invokeLater(() -> {
      //mainTabbedPane = new JTabbedPane();
      newTabButton = new JPanel();
      newTabButton.setName("...");
      mainTabbedPane = new JTabbedPane();
      mainTabbedPane.add(newTabButton);

      String b64ConfigurationJson = callbacks.loadExtensionSetting(getTabCaption());
      if (b64ConfigurationJson != null) {
        System.out.println("Loading Stored AutoRepeater Configuration");
        JsonParser jsonParser = new JsonParser();
        String configurationJson = new String(Base64.getDecoder().decode(b64ConfigurationJson));
        JsonArray tabConfigurations = jsonParser.parse(configurationJson).getAsJsonArray();
        for (JsonElement tabConfiguration : tabConfigurations) {
          addNewTab(tabConfiguration.getAsJsonObject());
        }
      } else {
        addNewTab();
      }

      mainTabbedPane.addChangeListener(e -> {
        // Make all tabname not editable whenever the tab is changed
        if (!tabChangeListenerLock) {
          if (mainTabbedPane.getSelectedIndex() == mainTabbedPane.getTabCount() - 1) {
            addNewTab();
          }
        }
        for (int i = 0; i < mainTabbedPane.getTabCount() - 1; i++) {
          AutoRepeaterTabHandle arth = (AutoRepeaterTabHandle) mainTabbedPane.getTabComponentAt(i);
          arth.tabName.setEditable(false);
        }
      });

      // Set Extension Name
      callbacks.setExtensionName("AutoRepeater");
      // register As An HTTP Listener
      callbacks.registerHttpListener(BurpExtender.this);
      // Add To Right Click Menu
      callbacks.registerContextMenuFactory(BurpExtender.this);
      //Save State
      callbacks.registerExtensionStateListener(() -> {
        JsonArray BurpExtenderJson = new JsonArray();
        // Don't count the "..." tab
        for (int i = 0; i < mainTabbedPane.getTabCount() - 1; i++) {
          AutoRepeaterTabHandle autoRepeaterTabHandle = (AutoRepeaterTabHandle) mainTabbedPane
              .getTabComponentAt(i);
          AutoRepeater ar = autoRepeaterTabHandle.autoRepeater;
          JsonObject AutoRepeaterJson = ar.toJson();
          AutoRepeaterJson.addProperty("tabName", autoRepeaterTabHandle.tabName.getText());
          BurpExtenderJson.add(AutoRepeaterJson);
        }
        callbacks.saveExtensionSetting(getTabCaption(), new String(
            Base64.getEncoder().encode(BurpExtenderJson.toString().getBytes()))
        );
      });
      // Add A Custom Tab To Burp
      callbacks.addSuiteTab(BurpExtender.this);
      // set parent component
      parentTabbedPane = (JTabbedPane) getUiComponent().getParent();
      //Utils.highlightParentTab((JTabbedPane) getUiComponent().getParent(), getUiComponent());
    });
  }

  private void addNewTab(JsonObject tabContents) {
    String tabName = tabContents.get("tabName").getAsString();
    tabChangeListenerLock = true;
    tabCounter += 1;
    AutoRepeater autoRepeater = new AutoRepeater(tabContents);
    autoRepeaters.add(autoRepeater);
    mainTabbedPane.add(autoRepeater.getUI());
    AutoRepeaterTabHandle autoRepeaterTabHandle = new AutoRepeaterTabHandle(tabName, autoRepeater);
    mainTabbedPane.setTabComponentAt(mainTabbedPane.indexOfComponent(autoRepeater.getUI()),
        autoRepeaterTabHandle);
    // Hack to steal and remove focus
    mainTabbedPane.remove(newTabButton);
    mainTabbedPane.add(newTabButton);
    tabChangeListenerLock = false;
  }

  private void addNewTab() {
    tabChangeListenerLock = true;
    tabCounter += 1;
    AutoRepeater autoRepeater = new AutoRepeater();
    autoRepeaters.add(autoRepeater);
    mainTabbedPane.add(autoRepeater.getUI());
    AutoRepeaterTabHandle autoRepeaterTabHandle = new AutoRepeaterTabHandle(
        Integer.toString(tabCounter), autoRepeater);
    mainTabbedPane.setTabComponentAt(mainTabbedPane.indexOfComponent(autoRepeater.getUI()),
        autoRepeaterTabHandle);
    // Hack to steal and remove focus
    mainTabbedPane.remove(newTabButton);
    mainTabbedPane.add(newTabButton);
    tabChangeListenerLock = false;
  }

  public static void highlightTab() {
    if (parentTabbedPane != null) {
      for (int i = 0; i < parentTabbedPane.getTabCount(); i++) {
        if (parentTabbedPane.getComponentAt(i).equals(mainTabbedPane)) {
          parentTabbedPane.setBackgroundAt(i, Utils.getBurpOrange());
          Timer timer = new Timer(3000, e -> {
            for (int j = 0; j < parentTabbedPane.getTabCount(); j++) {
              if (parentTabbedPane.getComponentAt(j).equals(mainTabbedPane)) {
                parentTabbedPane.setBackgroundAt(j, Color.BLACK);
                break;
              }
            }
          });
          timer.setRepeats(false);
          timer.start();
          break;
        }
      }
    }
  }

  // implement ITab
  @Override
  public String getTabCaption() {
    return "AutoRepeater";
  }

  @Override
  public Component getUiComponent() {
    return mainTabbedPane;
  }

  // implement IHttpListener
  @Override
  public void processHttpMessage(int toolFlag, boolean messageIsRequest,
      IHttpRequestResponse messageInfo) {
    for (AutoRepeater autoRepeater : autoRepeaters) {
      autoRepeater.modifyAndSendRequestAndLog(toolFlag, messageIsRequest, messageInfo, false);
    }
  }

  private class AutoRepeaterTabHandle extends JPanel {

    AutoRepeater autoRepeater;
    JTextField tabName;

    private AutoRepeaterTabHandle(String title, AutoRepeater autoRepeater) {
      this.autoRepeater = autoRepeater;
      this.setLayout(new FlowLayout(FlowLayout.LEFT, 0, 0));
      this.setOpaque(false);
      JLabel label = new JLabel(title);
      label.setBorder(BorderFactory.createEmptyBorder(1, 2, 1, 2));
      tabName = new JTextField(title);
      tabName.setOpaque(false);
      tabName.setBorder(null);
      tabName.setBackground(new Color(0, 0, 0, 0));
      tabName.setEditable(false);
      tabName.setCaretColor(Color.BLACK);

      this.add(tabName);
      JButton closeButton = new JButton("✕");
      closeButton.setFont(new Font("monospaced", Font.PLAIN, 10));
      closeButton.setBorder(BorderFactory.createEmptyBorder(1, 2, 1, 2));
      closeButton.setForeground(Color.GRAY);

      closeButton.setBorderPainted(false);
      closeButton.setContentAreaFilled(false);
      closeButton.setOpaque(false);

      tabName.addMouseListener(new MouseAdapter() {
        @Override
        public void mouseClicked(MouseEvent e) {
          if (!mainTabbedPane.getSelectedComponent().equals(autoRepeater.getUI())) {
            mainTabbedPane.setSelectedComponent(autoRepeater.getUI());
            for (int i = 0; i < mainTabbedPane.getTabCount() - 2; i++) {
              if (!mainTabbedPane.getComponentAt(i).equals(autoRepeater.getUI())) {
                AutoRepeaterTabHandle autoRepeaterTabHandle =
                    (AutoRepeaterTabHandle) mainTabbedPane.getTabComponentAt(i);
                autoRepeaterTabHandle.tabName.setEditable(false);
              }
            }
          } else {
            mainTabbedPane.setSelectedComponent(autoRepeater.getUI());
            tabName.setEditable(true);
          }
        }

        @Override
        public void mousePressed(MouseEvent e) {
          if (!mainTabbedPane.getSelectedComponent().equals(autoRepeater.getUI())) {
            mainTabbedPane.setSelectedComponent(autoRepeater.getUI());
            for (int i = 0; i < mainTabbedPane.getTabCount() - 2; i++) {
              if (!mainTabbedPane.getComponentAt(i).equals(autoRepeater.getUI())) {
                AutoRepeaterTabHandle arth = (AutoRepeaterTabHandle) mainTabbedPane
                    .getTabComponentAt(i);
                arth.tabName.setEditable(false);
              }
            }
          } else {
            mainTabbedPane.setSelectedComponent(autoRepeater.getUI());
          }
        }
      });

      closeButton.addActionListener(e -> {
        tabChangeListenerLock = true;
        if (mainTabbedPane.getSelectedComponent().equals(autoRepeater.getUI())) {
          if (mainTabbedPane.getTabCount() == 2) {
            mainTabbedPane.remove(autoRepeater.getUI());
            autoRepeaters.remove(autoRepeater);
            addNewTab();
            tabChangeListenerLock = true;
          } else if (mainTabbedPane.getTabCount() > 2) {
            mainTabbedPane.remove(autoRepeater.getUI());
            autoRepeaters.remove(autoRepeater);
          }

          if (mainTabbedPane.getSelectedIndex() == mainTabbedPane.getTabCount() - 1) {
            mainTabbedPane.setSelectedIndex(mainTabbedPane.getTabCount() - 2);
          }
        } else {
          mainTabbedPane.setSelectedComponent(autoRepeater.getUI());
        }
        tabChangeListenerLock = false;
      });

      this.add(closeButton);
    }
  }

  public static IBurpExtenderCallbacks getCallbacks() {
    return callbacks;
  }

  public static IExtensionHelpers getHelpers() {
    return helpers;
  }

  public static Gson getGson() {
    return gson;
  }

  @Override
  public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
    ArrayList<JMenuItem> menu = new ArrayList<>();
    ActionListener listener;
    final int toolFlag = invocation.getToolFlag();
    IHttpRequestResponse[] requestResponses = invocation.getSelectedMessages();

    listener = event -> new Thread(() -> {
      if (toolFlag != -1) {
        //Utils.highlightParentTab((JTabbedPane) getUiComponent().getParent(), getUiComponent());
        for (AutoRepeater autoRepeater : autoRepeaters) {
          for (IHttpRequestResponse requestResponse : requestResponses) {
            autoRepeater.modifyAndSendRequestAndLog(toolFlag, true, requestResponse, true);
          }
        }
      }
    }).start();

    JMenuItem item = new JMenuItem("Send to AutoRepeater", null);
    item.addActionListener(listener);
    menu.add(item);
    return menu;
  }
}
