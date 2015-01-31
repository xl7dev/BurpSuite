burp-protobuf-decoder
=====================

A simple Google Protobuf Decoder for Burp


Prerequisites
-------------

1. Download and install the [protoc](https://code.google.com/p/protobuf/).
2. Burp Professional 1.5.01+
3. [Jython 2.7+](http://www.jython.org/downloads.html)


Install
-------

1. In Burp Extender tab, click Add
1. Select the Extension type: Python
1. Select the `protoburp.py` file
1. Click Next

The extension should be installed.


Frequently Asked Questions
--------------------------

1. Why can't I edit a decoded proto message?

	> Serializing a message requires a proto file descriptor (\*.proto file).
	> Without this proto, we don't know how fields should be serialized.

1. What if I have a proto file descriptor?

	> Load it from a Protobuf tab by right-clicking. Messages will be
	> automatically decoded from then on. If you wish to manually
	> deserialize a message as different type, this option is available to you 
	> via a right-click context menu once a proto is loaded.

	> By loading a .proto, you can edit and tamper protobuf messages.
	> The extension will automatically serialize messages back before
	> they're sent along.

1. Can I deserialize protobufs passed as URL or form parameters?

    > Yes, you can. In the 'Protobuf Editor' tab, add a parameter to
    > the table. You can specify additional pre and post processing
    > rules, to handle base64 encoding or zlib compression. Don't forget
    > to check the enabled box for each rule once you're done.

    > Note, the editor tab window may not immediately pick up the changes.
    > You can work around this issue by cycling through requests (anything
    > that'd trigger the editor tab to reload itself)
