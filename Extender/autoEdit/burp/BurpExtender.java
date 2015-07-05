package burp;

// Awt
import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
// Swing
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;
import javax.swing.JButton;
import javax.swing.JList;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JComboBox;
import javax.swing.DefaultListModel;
import javax.swing.JCheckBox;
import javax.swing.BoxLayout;
import javax.swing.ListSelectionModel;
import javax.swing.JOptionPane;
// Util
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
// IO
import java.io.PrintWriter;
// Net
import java.net.URL;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab, ActionListener
{
	private IExtensionHelpers helpers = null;
	private IBurpExtenderCallbacks callbacks = null;
	private JPanel mainPanel = null;

	private boolean isActive = false;
	private int method = 0;
	private JCheckBox enableCheckBox = null;
	private JTextField urlTextField = null;
	private JTextField paramTextField = null;
	private JTextArea logTextArea = null;
	private JList paramsList = null;
	private DefaultListModel paramsListModel = null;
	private JComboBox methodBox = null;

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
	{
		this.callbacks = callbacks;
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName("autoEdit");
		callbacks.registerHttpListener(this);

		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				mainPanel = new JPanel(new BorderLayout());
				mainPanel.setLayout(new BorderLayout());

				// North
				JPanel northPanel = new JPanel();
				northPanel.setLayout(new FlowLayout());
				enableCheckBox = new JCheckBox("disabled", isActive);
				enableCheckBox.setActionCommand("changestate");
				enableCheckBox.addActionListener(BurpExtender.this);
				urlTextField = new JTextField(40);
				urlTextField.setText("https?://www.google.fr/");
				northPanel.add(enableCheckBox);
				northPanel.add(new JLabel(" |  url (regex)  "));
				northPanel.add(urlTextField);
				JButton clearLogButton = new JButton("clear logs");
				clearLogButton.setActionCommand("clear_log");
				clearLogButton.addActionListener(BurpExtender.this);
				northPanel.add(clearLogButton);
				mainPanel.add(northPanel, BorderLayout.NORTH);

				// East
				JPanel eastPanel = new JPanel();
				eastPanel.setLayout(new BoxLayout(eastPanel, BoxLayout.PAGE_AXIS));
					// East-North
					JPanel eastNPanel = new JPanel();
					eastNPanel.setLayout(new FlowLayout());
					paramTextField = new JTextField(10);
					String[] methods =
					{
						"base64_encode",
						"base64_decode",
						"url_encode",
						"url_decode",
						"double_url_encode",
						"double_url_decode",
						"strange",
						"serialize_php",
						"serialize_php_b64",
						"xor"
					};
					methodBox = new JComboBox(methods);
					methodBox.setSelectedIndex(0);
					JButton addParamButton = new JButton("add");
					addParamButton.setActionCommand("add_param");
					addParamButton.addActionListener(BurpExtender.this);
					eastNPanel.add(paramTextField);
					eastNPanel.add(methodBox);
					eastNPanel.add(addParamButton);
				paramsListModel = new DefaultListModel();
				paramsList = new JList(paramsListModel);
				paramsList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
				paramsList.setVisibleRowCount(40);
					// East-South
					JPanel eastSPanel = new JPanel();
					eastSPanel.setLayout(new FlowLayout());
					JButton delParamButton = new JButton("del");
					delParamButton.setActionCommand("del_param");
					delParamButton.addActionListener(BurpExtender.this);
					JButton dellAllParamsButton = new JButton("del all");
					dellAllParamsButton.setActionCommand("del_all_params");
					dellAllParamsButton.addActionListener(BurpExtender.this);
					eastSPanel.add(delParamButton);
					eastSPanel.add(dellAllParamsButton);
				eastPanel.add(new JLabel("- Parameters -"));
				eastPanel.add(eastNPanel);
				eastPanel.add(new JScrollPane(paramsList));
				eastPanel.add(eastSPanel);

				// Center
				logTextArea = new JTextArea();
				logTextArea.setEditable(false);
				logTextArea.setAutoscrolls(true);
				logTextArea.setLineWrap(true);
				logTextArea.setFocusable(true);
				mainPanel.add(new JScrollPane(logTextArea), BorderLayout.CENTER);
				mainPanel.add(eastPanel, BorderLayout.EAST);

				callbacks.customizeUiComponent(mainPanel);
				callbacks.addSuiteTab(BurpExtender.this);
			}
		});
	}

	@Override
	public String getTabCaption()
	{
		return "autoEdit";
	}

	@Override
	public Component getUiComponent()
	{
		return this.mainPanel;
	}

	@Override
	public void actionPerformed(ActionEvent e)
	{
		if(e.getActionCommand().equals("add_param"))
		{
			String paramName = paramTextField.getText();
			boolean isIn = false; int i = 0;
			for(;i<paramsListModel.getSize();i++)
			{
				ParamM current = (ParamM)paramsListModel.getElementAt(i);
				if(current.getParamName().equals(paramName))
				{
					isIn = true;
					break;
				}
			}

			if(!paramName.equals("") && !isIn)
			{
				// new one, create new ParamM
				String methodS = (String)methodBox.getSelectedItem();
				ParamM current;
				if(methodS.equals("xor"))
				{
					String valueS = (String)JOptionPane.showInputDialog("Key for XOR :", "");
					current = new ParamM(paramName, methodS, valueS);
				}
				else
				{
					current = new ParamM(paramName, methodS);
				}
				paramsListModel.addElement(current);
			}else if(!paramName.equals("") && isIn)
			{
				// existing, just update the method and param
				String methodS = (String)methodBox.getSelectedItem();
				ParamM current = (ParamM)paramsListModel.getElementAt(i);
				if(methodS.equals("xor"))
				{
					String valueS = (String)JOptionPane.showInputDialog("Key for XOR :", "");
					current.setMethod(methodS);
					current.setValue(valueS);
				}
				else
				{
					current.setMethod(methodS);
				}
			}
			paramsList.updateUI();
			paramTextField.setText("");
		}
		if(e.getActionCommand().equals("del_param"))
		{
			int indexes[] = paramsList.getSelectedIndices();
			for(int i=indexes.length-1;i>=0;i--)
			{
				paramsListModel.remove(indexes[i]);
			}
		}
		if(e.getActionCommand().equals("del_all_params"))
		{
			paramsListModel.removeAllElements();
		}
		if(e.getActionCommand().equals("changestate"))
		{
			if(isActive)
			{
				isActive = false;
				enableCheckBox.setSelected(false);
				enableCheckBox.setText("disabled");
			}
			else
			{
				isActive = true;
				enableCheckBox.setSelected(true);
				enableCheckBox.setText("enabled");
			}
		}
		if(e.getActionCommand().equals("clear_log"))
		{
			logTextArea.setText("");
		}
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
	{
		if(isActive && messageIsRequest)
		{
			IParameter parameter = helpers.getRequestParameter(messageInfo.getRequest(), paramTextField.getText());
			URL currentUrl = helpers.analyzeRequest(messageInfo).getUrl();
			Pattern pattern = Pattern.compile(urlTextField.getText(), Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
			String url1 = currentUrl.getProtocol()+"://"+currentUrl.getHost()+":"+currentUrl.getPort()+currentUrl.getPath()+"?"+currentUrl.getQuery();
			String url2 = currentUrl.getProtocol()+"://"+currentUrl.getHost()+currentUrl.getPath()+"?"+currentUrl.getQuery();
			if(pattern.matcher(url1).find() || pattern.matcher(url2).find())
			{
				// URL OK
				String curParamToChange = "";
				List<IParameter> listParams = helpers.analyzeRequest(messageInfo).getParameters();

				log("[+] URL : "+currentUrl.toString());
				for(int i=0;i<listParams.size();i++)
				{
					IParameter cur = listParams.get(i);
					for(int v=0;v<paramsListModel.getSize(); v++)
					{
						ParamM current = (ParamM)paramsListModel.getElementAt(v);
						if(current.getParamName().equals(cur.getName()))
						{
							// Current param OK
							String newValue = calNewValue(cur.getValue(), (ParamM)paramsListModel.getElementAt(v));
							IParameter newParameter = helpers.buildParameter(cur.getName(), newValue, cur.getType());
							byte[] newRequest = helpers.updateParameter(messageInfo.getRequest(), newParameter);
							messageInfo.setRequest(newRequest);
							log("[out] "+cur.getName()+":"+cur.getValue()+" -> "+cur.getName()+":"+newValue);
						}
					}
				}
				log("");
			}
		}
	}

	// Next, some functions not overriden
	public String calNewValue(String value, ParamM param)
	{
		String method = param.getMethod();
		if(method.equals("base64_encode"))
			return (new String(helpers.base64Encode(value.getBytes())));
		else if(method.equals("base64_decode"))
			return (new String(helpers.base64Decode(value.getBytes())));
		else if(method.equals("url_encode"))
			return helpers.urlEncode(value);
		else if(method.equals("url_decode"))
			return helpers.urlDecode(value);
		else if(method.equals("double_url_encode"))
			return helpers.urlEncode(helpers.urlEncode(value));
		else if(method.equals("double_url_decode"))
			return helpers.urlDecode(helpers.urlDecode(value));
		else if(method.equals("strange"))
		{
			String result = "";
			value = helpers.urlDecode(new String(value.getBytes()));
			for(int i=0;i<value.length();i++)
			{
				int cur = (int)value.charAt(i);
				cur ^= 192;
				if(cur < 10)
					result = result + "00" + cur;
				else if(cur < 100)
					result = result + "0" + cur;
				else
					result = result + cur;
			}
			result = helpers.base64Encode(result.getBytes());
			return result;
		}
		else if(method.equals("serialize_php"))
		{
			if(value.indexOf(";") > -1)
			{
				String enums[] = value.split(";");
				String retour = "a:"+(enums.length)+":{";
				for(int i=0;i<enums.length;i++)
				{
					String name = enums[i].split("=")[0];
					String val = enums[i].split("=")[1];
					retour = retour +"s:"+name.length()+":\""+name+"\";s:"+val.length()+":\""+val+"\";";
				}
				retour = retour +"}";
				log("[serialize_php] payload before base64_encode : "+retour);
				return retour;
			}
			return value;
		}
		else if(method.equals("serialize_php_b64"))
		{
			if(value.indexOf(";") > -1)
			{
				String enums[] = value.split(";");
				String retour = "a:"+(enums.length)+":{";
				for(int i=0;i<enums.length;i++)
				{
					String name = enums[i].split("=")[0];
					String val = enums[i].split("=")[1];
					retour = retour +"s:"+name.length()+":\""+name+"\";s:"+val.length()+":\""+val+"\";";
				}
				retour = retour +"}";
				log("[serialize_php_b64] payload before base64_encode : "+retour);
				return (new String(helpers.base64Encode(retour.getBytes())));
			}
			log("[serialize_php_b64] format error, expected one : login=name1=param1;name2=param2;");
			return value;
		}
		else if(method.equals("xor"))
		{
			StringBuilder sb = new StringBuilder();
			String key = param.getValue();
			for(int i=0;i<value.length();i++)
				sb.append((char)(value.charAt(i) ^ key.charAt(i % key.length())));
			return sb.toString();
		}
		else
			return value;
	}
	
	public void log(String text)
	{
		logTextArea.append(text);
		logTextArea.append("\n");
		logTextArea.setCaretPosition(logTextArea.getDocument().getLength());
	}
}

class ParamM
{
	private String value;
	private String param_name;
	private String method;

	public ParamM(String param_name, String method, String value)
	{
		this.param_name = param_name;
		this.method = method;
		this.value = value;
	}

	public ParamM(String param_name, String method)
	{
		this(param_name, method, "");
	}

	public String getParamName()
	{
		return this.param_name;
	}

	public String getMethod()
	{
		return this.method;
	}

	public void setMethod(String method)
	{
		this.method = method;
	}

	public void setValue(String value)
	{
		this.value = value;
	}

	public String getValue(){
		return this.value;
	}

	public String toString()
	{
		if(this.value.equals(""))
			return param_name+" -> "+method;
		else
			return this.param_name+" -> "+this.method+" ("+this.value+")";
	}
}
