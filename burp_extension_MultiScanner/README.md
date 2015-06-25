                                          Multi-Scanner Burp Extension

More information can be found in Readme.doc

Introduction: 
Multi-Scanner is an extension to the burp suite. It automates the task of making requests to target websites posing as a 
variety of devices. 

Mobile versions of sites may be different due to

•Different programmers

•Different functionalities (e.g. hover is not possible on a mobile device)

•Compatibility issues (e.g. flash)

Without the extension a penetration tester would have to manually intercept the requests, modify them before forwarding, 
compare the responses and finally call active scans on each of them. This can be done for a few requests on a few pages 
but will quickly become a problem when the scale increases. Multi-Scanner provides an efficient and scalable mechanism 
to carry out these tasks automatically.

Currently it requests the target web pages with the following list of user agents

1.Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:16.0) Gecko/20100101 Firefox/16.0

2.Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3

3.Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3

4.Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30

5.Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0; SAMSUNG; SGH-i917)

6.Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone 8.0; Trident/6.0; IEMobile/10.0; ARM; Touch; NOKIA; Lumia 920)

7.Mozilla/5.0 (BlackBerry; U; BlackBerry 9900; en) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.1.0.346 Mobile Safari/534.11+

This list can be easily augmented to include more devices/browsers.
The response is then captured for each user agent. The first user agent is a baseline user agent which all the others 
(mobile devices) are compared against. If the responses are found to be the same the extension alerts the user and 
does no further work. If differences are found, the extension proceeds to do an active scan on all the versions. 
https is also supported.
