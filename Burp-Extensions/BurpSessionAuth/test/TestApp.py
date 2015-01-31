#!/usr/bin/python3

import cgi
import html

testcases = {
    'ScanValueAppearsExactly': {
        '123': 'AccessibleContent xxx AccessibleContent',
        '456': 'ProtectedContent xxx ProtectedContent'
        },
    'ScanValueAppearsFuzzy': {
        '123': 'AccessibleContent xxx AccessibleContent',
        '456': 'ProtectedContent xxx'
        },
    'DecreaseIncrease': {
        '123': 'AccessibleContent xxx AccessibleContent xxx ProtectedContent xxx ProtectedContent',
        '456': 'AccessibleContent xxx ProtectedContent xxx ProtectedContent xxx ProtectedContent'
        },
    'ScanValueIncrease': {
        '123': 'AccessibleContent xxx AccessibleContent xxx ProtectedContent xxx ProtectedContent',
        '456': 'AccessibleContent xxx AccessibleContent xxx ProtectedContent xxx ProtectedContent xxx ProtectedContent'
        },
    'ScanValueNotFound': {
        '123': 'xxx xxx xxx',
        '456': 'xxx yyy xxx'
        },
    'Other': {
        '123': 'AccessibleContent xxx AccessibleContent',
        '456': 'AccessibleContent xxx AccessibleContent xxx'
        },
    'NoDiff': {
        '123': 'AccessibleContent xxx AccessibleContent',
        '456': 'AccessibleContent xxx AccessibleContent'
        }
    }

print("Content-Type: text/html")
print("")

param = cgi.FieldStorage()
testtype = param.getfirst('type') or "<none>"
ident = param.getfirst('id') or "<none>"

if testtype in testcases:
    if ident in testcases[testtype]:
        print(testcases[testtype][ident])
else:
    print("<h1>Burp SessionAuth Plugin Tests</h1>")
    print("type=" + html.escape(testtype) + ", id=" + html.escape(ident) + "<hr />")
    print("<h2>IDs and Content Values</h2>");
    print("Configure the following identifiers and content values in Burp SessionAuth extension:")
    print("<ul><li>id=123: AccessibleContent</li><li>id=456: ProtectedContent</li></ul>")
    print("<h2>Test Types</h2>")
    print("<ul>")
    for testcase in testcases:
        print("<li><a href=\"?type=" + testcase + "&id=123\">" + testcase + "</a></li>")
    print("</ul>");
