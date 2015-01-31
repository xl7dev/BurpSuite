package burp.JSBeautifier;
import java.util.prefs.Preferences;

public class BeautifierPreferences {
	private static Preferences prefs=Preferences.userRoot().node("JSBeautifier");
	private static final double version = 1.2;
	private static final String appName = "Burp Suite JSBeautifier";
	private static final String author = "Soroush Dalili (@irsdl)";
	private static final String authorLink = "https://secproject.com/";
	private static final String projectLink = "https://github.com/irsdl/BurpSuiteJSBeautifier";
	
	public synchronized static double getVersion() {
		return version;
	}
	
	public synchronized static String getProjectLink() {
		return projectLink;
	}
	public synchronized static String getAppInfo() {
		return "Name: "+appName + " -Version: " + String.valueOf(version) + " -Source: " + projectLink + " -Author: " + author;
	}
	  
	public synchronized static boolean isDebugMode() {
		return prefs.getBoolean("isDebugMode", false);
	}


	public synchronized static void setDebugMode(boolean isDebugMode) {
		prefs.putBoolean("isDebugMode", isDebugMode);
	}


	public synchronized static boolean isAutomaticInProxy() {
		return prefs.getBoolean("isAutomaticInProxy", false);
	}


	public synchronized static void setAutomaticInProxy(boolean isAutomaticInProxy) {
		prefs.putBoolean("isAutomaticInProxy", isAutomaticInProxy);
	}

	public synchronized static boolean isRestrictedToScope() {
		return prefs.getBoolean("isRestrictedToScope", false);
	}


	public synchronized  static void setRestrictedToScope(boolean isRestrictedToScope) {
		prefs.putBoolean("isRestrictedToScope", isRestrictedToScope);
	}
	
	public synchronized  static int getIndent_size() {
		return prefs.getInt("indent_size", 1);
	}


	public synchronized  static void setIndent_size(int indent_size) {
		prefs.putInt("indent_size", indent_size);
	}


	public synchronized  static String getIndent_char() {
		if(getIndent_size()==1){
			return prefs.get("indent_char", "\\t");
		}else{
			return prefs.get("indent_char", " ");
		}
	}


	public synchronized static void setIndent_char(String indent_char) {
		prefs.put("indent_char", indent_char);
	}


	public synchronized static int getMax_preserve_newlines() {
		return prefs.getInt("max_preserve_newlines", 5);
	}


	public synchronized static void setMax_preserve_newlines(int max_preserve_newlines) {
		prefs.putInt("max_preserve_newlines", max_preserve_newlines);
	}


	public synchronized static boolean isPreserve_newlines() {
		return getMax_preserve_newlines()!=-1;
	}


//	public synchronized static void setPreserve_newlines(boolean preserve_newlines) {
//		prefs.putBoolean("preserve_newlines", preserve_newlines);
//	}


	public synchronized static boolean isKeep_array_indentation() {
		return prefs.getBoolean("keep_array_indentation", false);
	}


	public synchronized static void setKeep_array_indentation(
			boolean keep_array_indentation) {
		prefs.putBoolean("keep_array_indentation", keep_array_indentation);
	}


	public synchronized static boolean isBreak_chained_methods() {
		return prefs.getBoolean("break_chained_methods", false);
	}


	public synchronized static void setBreak_chained_methods(boolean break_chained_methods) {
		prefs.putBoolean("break_chained_methods", break_chained_methods);
	}


	public synchronized static boolean isSpace_after_anon_function() {
		return prefs.getBoolean("space_after_anon_function", true);
	}


	public synchronized static void setSpace_after_anon_function(
			boolean space_after_anon_function) {
		prefs.putBoolean("space_after_anon_function", space_after_anon_function);
	}


	public synchronized static String getIndent_scripts() {
		return prefs.get("indent_scripts", "nomral");
	}


	public synchronized static void setIndent_scripts(String indent_scripts) {
		prefs.put("indent_scripts", indent_scripts);
	}


	public synchronized static String getBrace_style() {
		return prefs.get("brace_style", "expand");
	}


	public synchronized static void setBrace_style(String brace_style) {
		prefs.put("brace_style", brace_style);
	}


	public synchronized static boolean isSpace_before_conditional() {
		return prefs.getBoolean("space_before_conditional", false);
	}


	public synchronized static void setSpace_before_conditional(
			boolean space_before_conditional) {
		prefs.putBoolean("space_before_conditional", space_before_conditional);
	}


	public synchronized static boolean isDetect_packers() {
		return prefs.getBoolean("detect_packers", true);
	}


	public synchronized static void setDetect_packers(boolean detect_packers) {
		prefs.putBoolean("detect_packers", detect_packers);
	}


	public synchronized static boolean isUnescape_strings() {
		return prefs.getBoolean("unescape_strings", false);
	}


	public synchronized static void setUnescape_strings(boolean unescape_strings) {
		prefs.putBoolean("unescape_strings", unescape_strings);
	}


	public synchronized static int getWrap_line_length() {
		return prefs.getInt("wrap_line_length", 0);
	}


	public synchronized static void setWrap_line_length(int wrap_line_length) {
		prefs.putInt("wrap_line_length", wrap_line_length);
	}
	
	public synchronized static boolean isBeautifyHeadersInManualMode() {
		return prefs.getBoolean("isBeautifyHeadersInManualMode", false);	
	}
	
	public static void setBeautifyHeadersInManualMode(boolean isBeautifyHeadersInManualMode) {
		prefs.putBoolean("isBeautifyHeadersInManualMode", isBeautifyHeadersInManualMode);
	}
	
	public static boolean isAutomaticInAll() {
		return prefs.getBoolean("isAutomaticInAll", false);	
	}

	public static void setAutomaticInAll(boolean isAutomaticInAll) {
		prefs.putBoolean("isAutomaticInAll", isAutomaticInAll);
	}
	
	public static void resetBeautifierPreferences(){
		setAutomaticInProxy(false);
		setRestrictedToScope(false);
		setAutomaticInAll(false);
		setBeautifyHeadersInManualMode(false);
		setDebugMode(false);
		setIndent_size(1);
		setIndent_char("\\t");
		setMax_preserve_newlines(5);
		//setPreserve_newlines(true);
		setKeep_array_indentation(false);
		setBreak_chained_methods(false);
		setSpace_after_anon_function(true);
		setIndent_scripts("normal");
		setBrace_style("expand");
		setSpace_before_conditional(false);
		setDetect_packers(true);
		setUnescape_strings(false);
		setWrap_line_length(0);
	}


}
