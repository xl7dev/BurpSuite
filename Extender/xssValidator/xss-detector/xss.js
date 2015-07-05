/**
 * This is a basic phantomJS script that will be used together
 * with the xssValidator burp extender.
 *
 * This script launches a web server that listens by default 
 * on 127.0.0.1:8093. The server listens for POST requests with 
 * http-response data.
 *
 * http-response should contain base64 encoded HTTP response as
 * passed from burp intruder. The server will decode this data, 
 * and build a WebPage bassed of the markup provided.
 *
 * The WebPage will be injected with the js-overrides.js file, 
 * which contains triggers for suspicious JS functions, such as
 * alert, confirm, etc. The page will be evaluated, and the DOM
 * triggers will alert us of any suspicious JS.
*/
var DEBUG = false

var system = require('system');
var fs = require('fs');

// Create xss object that will be used to track XSS information
var xss = new Object();
xss.value = 0;
xss.msg = "";

// Create webserver object
var webserver = require('webserver');
server = webserver.create();

// Server config details
var host = '127.0.0.1';
var port = '8093';

/**
 * parse incoming HTTP responses that are provided via BURP intruder.
 * data is base64 encoded to prevent issues passing via HTTP.
 *
 * This function appends the js-overrides.js file to all responses
 * to inject xss triggers into every page. Webkit will parse all responses
 * and alert us of any seemingly malicious Javascript execution, such as
 * alert, confirm, fromCharCode, etc.
 */
parsePage = function(data) {
	if (DEBUG) {	
		console.log("Beginning to parse page");
	}

	var html_response = "";
	wp.content = data;

	// Evaluate page, rendering javascript
	xssInfo = wp.evaluate(function (wp) {
		// Return information from page, if necessary
	}, wp);

	if(xss) {
		// xss detected, return
		return xss;
	}
	return false;
};

/**
 * After retriving data it is important to reinitialize certain
 * variables, specifically those related to the WebPage objects.
 * Without reinitializing the WebPage object may contain old data,
 * and as such, trigger false-positive messages.
 */
reInitializeWebPage = function() {
	wp = new WebPage();
	xss = new Object();
	xss.value = 0;
	xss.msg = "";

	// web page settings necessary to adequately detect XSS
	wp.settings = {
		loadImages: true,
		localToRemoteUrlAccessEnabled: true,
		javascriptEnabled: true,
		webSecurityEnabled: false,
		XSSAuditingEnabled: false
	};

	// Custom handler for alert functionality
	wp.onAlert = function(msg) {
		console.log("On alert: " + msg);
		
		xss.value = 1;
		xss.msg += 'XSS found: alert(' + msg + ')';
	};

	wp.onConsoleMessage = function(msg) {
		console.log("On console.log: " + msg);
		
		xss.value = 1;
		xss.msg += 'XSS found: console.log(' + msg + ')';
	};

	wp.onConfirm = function(msg) {
		console.log("On confirm: " + msg);
		
		xss.value = 1;
		xss.msg += 'XSS found: confirm(' + msg + ')';
	};

	return wp;
};

// Initialize webpage to ensure that all variables are
// initialized.
var wp = reInitializeWebPage();

// Start web server and listen for requests
var service = server.listen(host + ":" + port, function(request, response) {
	
	if(DEBUG) {
		console.log("\nReceived request with method type: " + request.method);
	}

	// At this point in time we're only concerned with POST requests
	// As such, only process those.
	if(request.method == "POST") {
		if(DEBUG) {
			console.log("Processing Post Request");
		}

		// Grab pageResponse from POST Data and base64 decode.
		// pass result to parsePage function to search for XSS.
		var pageResponse = request.post['http-response'];
		pageResponse = atob(pageResponse);
		xssResults = parsePage(pageResponse);

		// Return XSS Results
		if(xssResults) {
			// XSS is found, return information here
			response.statusCode = 200;
			response.write(JSON.stringify(xssResults));
			response.close();
		} else {
			response.statusCode = 201;
			response.write("No XSS found in response");
			response.close();
		}
	} else {
		response.statusCode = 500;
		response.write("Server is only designed to handle GET requests");
		response.close();
	}

	// Re-initialize webpage after parsing request
	wp = reInitializeWebPage();
	pageResponse = null;
	xssResults = null;
});
	
