package burp;

/**
 * Created by j on 8/7/17.
 */

import burp.Utils.Utils;
import com.google.gson.*;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.swing.*;
import javax.swing.Timer;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory {

  // burp stuff
  private static IBurpExtenderCallbacks callbacks;
  private static IExtensionHelpers helpers;
  private static Gson gson;
  private static JTabbedPane mainTabbedPane;
  private static JTabbedPane parentTabbedPane;
  private static JPanel newTabButton;
  private ExecutorService executor;
  //private static ResponseStore responseStore;

  // Global state variables
  private static int tabCounter = 0;
  private static boolean tabChangeListenerLock = false;
  private static ArrayList<AutoRepeater> autoRepeaters;
  private static boolean showSettingsPanel = true;

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
    executor = Executors.newFixedThreadPool(20);
    //responseStore = new ResponseStore();
    // create our UI
    SwingUtilities.invokeLater(() -> {
      mainTabbedPane = new JTabbedPane();
      newTabButton = new JPanel();
      newTabButton.setName("...");
      mainTabbedPane = new JTabbedPane();
      mainTabbedPane.add(newTabButton);
      // If there is a saved extensionSetting load it.
      String b64ConfigurationJson = callbacks.loadExtensionSetting(getTabCaption());
      if (b64ConfigurationJson != null) {
        initializeFromSave(b64ConfigurationJson, true);
      } else {
        addNewTab();
      }
      mainTabbedPane.addChangeListener(e -> {
        // Make all tabname not editable whenever the tab is changed
        if (!tabChangeListenerLock) {
          if (mainTabbedPane.getSelectedIndex() == mainTabbedPane.getTabCount() - 1) {
          //Component selectedTabHandle =
          //    mainTabbedPane.getTabComponentAt(mainTabbedPane.getSelectedIndex());
          //if (selectedTabHandle.getName().equals("...")) {
            if (!tabChangeListenerLock) {
              addNewTab();
            }
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
      // Add response store
      //callbacks.registerHttpListener(responseStore);
      //Save State
      callbacks.registerExtensionStateListener(
          () -> callbacks.saveExtensionSetting(getTabCaption(), exportSave())
      );
      // Add A Custom Tab To Burp
      callbacks.addSuiteTab(BurpExtender.this);
      // set parent component
      parentTabbedPane = (JTabbedPane) getUiComponent().getParent();
      addMenuItem();
    });
  }

  public static JTabbedPane getParentTabbedPane() {
    return parentTabbedPane;
  }

  public static String exportSave() {
    JsonArray BurpExtenderJson = new JsonArray();
    // Don't count the "..." tab
    for (int i = 0; i < mainTabbedPane.getTabCount() - 1; i++) {
      AutoRepeaterTabHandle autoRepeaterTabHandle
          = (AutoRepeaterTabHandle) mainTabbedPane.getTabComponentAt(i);
      AutoRepeater ar = autoRepeaterTabHandle.autoRepeater;
      JsonObject AutoRepeaterJson = ar.toJson();
      AutoRepeaterJson.addProperty("tabName", autoRepeaterTabHandle.tabName.getText());
      BurpExtenderJson.add(AutoRepeaterJson);
    }
    //return new String(Base64.getEncoder().encode(BurpExtenderJson.toString().getBytes()));
    return BurpExtenderJson.toString();
  }

  public static String exportSave(AutoRepeater ar) {
    JsonArray BurpExtenderJson = new JsonArray();
    // Don't count the "..." tab
    for (int i = 0; i < mainTabbedPane.getTabCount() - 1; i++) {
      AutoRepeaterTabHandle autoRepeaterTabHandle
          = (AutoRepeaterTabHandle) mainTabbedPane.getTabComponentAt(i);
      AutoRepeater tempAR = autoRepeaterTabHandle.autoRepeater;
      if (ar.equals(tempAR)) {
        JsonObject AutoRepeaterJson = tempAR.toJson();
        AutoRepeaterJson.addProperty("tabName", autoRepeaterTabHandle.tabName.getText());
        BurpExtenderJson.add(AutoRepeaterJson);
      }
    }
    //return new String(Base64.getEncoder().encode(BurpExtenderJson.toString().getBytes()));
    return BurpExtenderJson.toString();
  }

  public static void initializeFromSave(String configuration, boolean replaceTabs) {
    getCallbacks().printOutput("Loading Stored AutoRepeater Configuration");
    String configurationJson;
    // Check if the configuration is B64 encoded for legacy.
    try {
      configurationJson = new String(Base64.getDecoder().decode(configuration));
    } catch (IllegalArgumentException e) {
      configurationJson = configuration;
    }
    JsonParser jsonParser = new JsonParser();
    JsonArray tabConfigurations = jsonParser.parse(configurationJson).getAsJsonArray();
    if (replaceTabs) {
      closeAllTabs();
    }
    for (JsonElement tabConfiguration : tabConfigurations) {
      addNewTab(tabConfiguration.getAsJsonObject());
    }
  }

  private static void addNewTab(JsonObject tabContents) {
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

  private static void addNewTab() {
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

  private static void addMenuItem() {
    if (parentTabbedPane != null) {
      JRootPane rootPane = parentTabbedPane.getRootPane();
      JMenuBar burpJMenuBar = rootPane.getJMenuBar();
      // Need to remove the existing Menu Bar to make sure the element corresponds to the
      // current AutoRepeater instance
      for (int i = 0; i < burpJMenuBar.getMenuCount(); i++) {
        if (burpJMenuBar.getMenu(i).getText().equals("AutoRepeater")) {
          burpJMenuBar.remove(i);
        }
      }
      JMenu autoRepeaterJMenu = new JMenu("AutoRepeater");
      JMenuItem toggleSettingsVisibility = new JMenuItem("Hide Settings Panel");
      toggleSettingsVisibility.addActionListener( c -> {
        if (toggleSettingsVisibility.getText().equals("Hide Settings Panel")) {
          showSettingsPanel = false;
          toggleSettingsVisibility.setText("Show Settings Panel");
        } else {
          showSettingsPanel = true;
          toggleSettingsVisibility.setText("Hide Settings Panel");
        }
        for (AutoRepeater ar : autoRepeaters) {
          ar.toggleConfigurationPane(showSettingsPanel);
        }
      });
      // Add the AutoRepeater menu item two from the end.
      autoRepeaterJMenu.add(toggleSettingsVisibility);
      burpJMenuBar.add(autoRepeaterJMenu, burpJMenuBar.getMenuCount()-2);
    }
  }

  public static boolean showSettingsPanel() {
    return showSettingsPanel;
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
  public void processHttpMessage(
      int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
    for (AutoRepeater autoRepeater : autoRepeaters) {
      //ExecutorService executor = new ThreadPoolExecutor(3, 3, 0L, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<Runnable>(15));
      executor.submit(
          () -> autoRepeater.modifyAndSendRequestAndLog(
              toolFlag,
              messageIsRequest,
              messageInfo,
             false)
      );
      //autoRepeater.modifyAndSendRequestAndLog(toolFlag, messageIsRequest, messageInfo, false);
    }
  }

  public static void closeAllTabs() {
    tabChangeListenerLock = true;
    int tabCount = mainTabbedPane.getTabCount()-1;
    for (int i = 0; i < tabCount; i++) {
      if (mainTabbedPane.getTabComponentAt(0).getClass().equals(AutoRepeaterTabHandle.class)) {
        try {
          AutoRepeaterTabHandle arth = (AutoRepeaterTabHandle) mainTabbedPane.getTabComponentAt(0);
          autoRepeaters.remove(arth.autoRepeater);
          mainTabbedPane.remove(0);
        } catch (Exception e) {
          getCallbacks().printOutput(e.getMessage());
        }
      }
    }
    tabChangeListenerLock = false;
  }

  private static class AutoRepeaterTabHandle extends JPanel {

    AutoRepeater autoRepeater;
    JTextField tabName;

    public AutoRepeaterTabHandle(String title, AutoRepeater autoRepeater) {
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

  public static ArrayList<AutoRepeater> getAutoRepeaters() {
    return autoRepeaters;
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
        BurpExtender.highlightTab();
        for (IHttpRequestResponse requestResponse : requestResponses) {
          final IHttpRequestResponse tempRequestResponse;
          if (requestResponse.getResponse() == null) {
            tempRequestResponse = BurpExtender.getCallbacks().makeHttpRequest(
                requestResponse.getHttpService(), requestResponse.getRequest());
          } else {
            tempRequestResponse = requestResponse;
          }
          executor.submit(() -> {
            for (AutoRepeater autoRepeater : autoRepeaters) {
              autoRepeater.modifyAndSendRequestAndLog(toolFlag, true, tempRequestResponse, true);
            }
          });
        }
      }
    }).start();

    JMenuItem item = new JMenuItem("Send to AutoRepeater", null);
    item.addActionListener(listener);
    menu.add(item);
    return menu;
  }
}
