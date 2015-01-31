# -*- coding: utf-8 -*-
from collections import OrderedDict
import base64
import importlib
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback

# Patch dir this file was loaded from into the path
# (Burp doesn't do it automatically)
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(
    inspect.getfile(inspect.currentframe()))), 'Lib'))

from burp import IBurpExtender, IMessageEditorTab, IMessageEditorTabFactory, ITab, \
        IExtensionStateListener

from google.protobuf.reflection import ParseMessage as parse_message
from google.protobuf.text_format import Merge as merge_message

from java.awt.event import ActionListener, MouseAdapter
from java.lang import Boolean, RuntimeException
from java.io import FileFilter
from javax.swing import JButton, JFileChooser, JMenu, JMenuItem, JOptionPane, JPanel, JPopupMenu
from javax.swing.filechooser import FileNameExtensionFilter

from ui import ParameterProcessingRulesTable


CONTENT_PROTOBUF = ('application/x-protobuf', 'application/octet-stream')
PROTO_FILENAME_EXTENSION_FILTER = FileNameExtensionFilter("*.proto, *.py",
                                                          ["proto", "py"])


class BurpExtender(IBurpExtender, IMessageEditorTabFactory, ITab, IExtensionStateListener):
    EXTENSION_NAME = "Protobuf Editor"

    def __init__(self):
        self.descriptors = OrderedDict()

        self.chooser = JFileChooser()
        self.chooser.addChoosableFileFilter(PROTO_FILENAME_EXTENSION_FILTER)
        self.chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES)
        self.chooser.setMultiSelectionEnabled(True)

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        self.enabled = False

        try:
            process = subprocess.Popen(['protoc', '--version'],
                                       stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
            output, error = process.communicate()
            self.enabled = output.startswith('libprotoc')

            if error:
                raise RuntimeError(error)

        except (OSError, RuntimeError) as error:
            self.callbacks.getStderr().write(
                    "Error calling protoc: %s\n" % (error.message, ))

        if not self.enabled:
            return

        rules = []
        saved_rules = callbacks.loadExtensionSetting('rules')

        if saved_rules:
            rules = json.loads(base64.b64decode(saved_rules))

            # For checkboxes to be rendered in a table model, the
            # type has to be java.lang.Boolean, not a Python bool.

            for rule in rules:
                rule[-1] = Boolean(rule[-1])

        self.table = ParameterProcessingRulesTable(self, *rules)

        callbacks.setExtensionName(self.EXTENSION_NAME)
        callbacks.registerExtensionStateListener(self)
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.addSuiteTab(self)
        return

    def createNewInstance(self, controller, editable):
        return ProtobufEditorTab(self, controller, editable)

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self.table

    def extensionUnloaded(self):
        if not self.table.rules:
            return

        rules = self.table.rules

        # The default JSONENcoder cannot dump a java.lang.Boolean type,
        # so convert it to a Python bool. (We'll have to change it back
        # when loading the rules again.

        for rule in rules:
            rule[-1] = bool(rule[-1])

        self.callbacks.saveExtensionSetting(
                'rules', base64.b64encode(json.dumps(rules)))
        return


class ProtobufEditorTab(IMessageEditorTab):
    TAB_CAPTION = "Protobuf"

    def __init__(self, extender, controller, editable):
        self.extender = extender
        self.callbacks = extender.callbacks
        self.helpers = extender.helpers
        self.controller = controller
        self.editable = editable

        self.descriptors = extender.descriptors
        self.chooser = extender.chooser

        self.listener = LoadProtoActionListener(self)

        self._current = (None, None, None, None)

        self.editor = extender.callbacks.createTextEditor()
        self.editor.setEditable(editable)

        mouseListener = LoadProtoMenuMouseListener(self)
        self.getUiComponent().addMouseListener(mouseListener)

    def getTabCaption(self):
        return self.TAB_CAPTION

    def getUiComponent(self):
        return self.editor.getComponent()

    def isEnabled(self, content, isRequest):
        if not self.extender.enabled:
            return False

        if isRequest:
            info = self.helpers.analyzeRequest(content)

            # check if request contains a specific parameter

            for parameter in info.getParameters():
                if parameter.getName() in self.extender.table.getParameterRules():
                    return True

            headers = info.getHeaders()
        else:
            headers = self.helpers.analyzeResponse(content).getHeaders()

        # first header is the request/response line

        for header in headers[1:]:
            name, _, value = header.partition(':')
            if name.lower() == 'content-type':
                value = value.lower().strip()
                if value in CONTENT_PROTOBUF:
                    return True

        return False

    def setMessage(self, content, isRequest):
        if content is None:
            self.editor.setText(None)
            self.editor.setEditable(False)
            return

        if isRequest:
            info = self.helpers.analyzeRequest(content)
        else:
            info = self.helpers.analyzeResponse(content)

        # by default, let's assume the entire body is a protobuf message

        body = content[info.getBodyOffset():].tostring()

        # process parameters via rules defined in Protobuf Editor ui tab

        parameter = None

        for name, rules in self.extender.table.getParameterRules().iteritems():
            parameter = self.helpers.getRequestParameter(content, name)

            if parameter is not None:

                # no longer use the entire message body as the protobuf
                # message, just the value of the parameter according
                # to our ui defined rules

                body = parameter.getValue().encode('utf-8')

                for rule in rules.get('before', []):
                    body = rule(body)

                break

        # Loop through all proto descriptors loaded

        for package, descriptors in self.descriptors.iteritems():
            for name, descriptor in descriptors.iteritems():

                try:
                    message = parse_message(descriptor, body)
                except Exception:
                    continue

                # Stop parsing on the first valid message we encounter
                # this may result in a false positive, so we should still
                # allow users to specify a proto manually (select from a
                # context menu).

                if message.IsInitialized():
                    self.editor.setText(str(message))
                    self.editor.setEditable(True)
                    self._current = (content, message, info, parameter)
                    return

        # If we get to this point, then no loaded protos could deserialize
        # the message. Shelling out to protoc should be a last resort.

        process = subprocess.Popen(['protoc', '--decode_raw'],
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)

        output = error = None
        try:
            output, error = process.communicate(body)
        except OSError:
            pass
        finally:
            if process.poll() != 0:
                process.wait()

        if error:
            self.editor.setText(error)
        else:
            self.editor.setText(output)

        self.editor.setEditable(False)
        self._current = (content, None, info, parameter)
        return

    def getMessage(self):
        content, message, info, parameter = self._current

        if message is not None and self.isModified():

            # store original so we can revert if needed

            original = message.SerializeToString()
            message.Clear()

            try:
                merge_message(self.editor.getText().tostring(), message)
                headers = info.getHeaders()
                serialized = message.SerializeToString()

                if parameter is not None:
                    rules = self.extender.table.getParameterRules().get(parameter.getName(), {})

                    for rule in rules.get('after', []):
                        serialized = rule(serialized)

                    param = self.helpers.buildParameter(
                            parameter.getName(), serialized, parameter.getType())

                    return self.helpers.updateParameter(content, param)
                else:
                    return self.helpers.buildHttpMessage(headers, serialized)

            except Exception as error:
                JOptionPane.showMessageDialog(self.getUiComponent(),
                    error.message, 'Error parsing message!',
                    JOptionPane.ERROR_MESSAGE)

                # an error occurred while re-serializing the message,
                # revert back to the original

                message.Clear()
                message.MergeFromString(original)

        return content

    def isModified(self):
        return self.editor.isTextModified()

    def getSelectedData(self):
        return self.editor.getSelectedText()


class LoadProtoMenuMouseListener(MouseAdapter):
    def __init__(self, tab):
        self.tab = tab

    def mousePressed(self, event):
        return self.handleMouseEvent(event)

    def mouseReleased(self, event):
        return self.handleMouseEvent(event)

    def handleMouseEvent(self, event):
        if event.isPopupTrigger():
            loadMenu = JMenuItem("Load .proto")
            loadMenu.addActionListener(self.tab.listener)

            popup = JPopupMenu()
            popup.add(loadMenu)

            if self.tab.descriptors:

                deserializeAsMenu = JMenu("Deserialize As...")

                popup.addSeparator()
                popup.add(deserializeAsMenu)

                for pb2, descriptors in self.tab.descriptors.iteritems():
                    subMenu = JMenu(pb2)
                    deserializeAsMenu.add(subMenu)

                    for name, descriptor in descriptors.iteritems():
                        protoMenu = JMenuItem(name)
                        protoMenu.addActionListener(
                            DeserializeProtoActionListener(self.tab, descriptor))

                        subMenu.add(protoMenu)

            popup.show(event.getComponent(), event.getX(), event.getY())

        return


class ListProtoFileFilter(FileFilter):
    def accept(self, f):
        basename, ext = os.path.splitext(f.getName())
        if ext == '.proto' or (ext == '.py' and basename.endswith('_pb2')):
            return True
        else:
            return False


class LoadProtoActionListener(ActionListener):
    def __init__(self, tab):
        self.chooser = tab.chooser
        self.descriptors = tab.descriptors
        self.tab = tab

    def updateDescriptors(self, name, module):
        if module.DESCRIPTOR.message_types_by_name and name not in self.descriptors:
            descriptors = self.descriptors.setdefault(name, {})
            descriptors.update(module.DESCRIPTOR.message_types_by_name)

        for name, module_ in inspect.getmembers(module, lambda x: hasattr(x, 'descriptor_pb2')):
            self.updateDescriptors(name, module_)

        return

    def importProtoFiles(self, selectedFiles):
        for selectedFile in selectedFiles:
            if selectedFile.isDirectory():
                self.chooser.setCurrentDirectory(selectedFile)
                self.importProtoFiles(selectedFile.listFiles(ListProtoFileFilter()))
            else:
                self.chooser.setCurrentDirectory(selectedFile.getParentFile())

                try:
                    module = compile_and_import_proto(selectedFile)
                    if module:
                        yield module

                except (Exception, RuntimeException) as error:
                    self.tab.callbacks.getStderr().write(
                        'Error importing proto %s!\n' % (selectedFile, ))

                    traceback.print_exc(file=self.tab.callbacks.getStderr())

                    JOptionPane.showMessageDialog(None,
                        '%s: %s' % (error.message, selectedFile),
                        'Error importing proto!', JOptionPane.ERROR_MESSAGE)

    def actionPerformed(self, event):
        if self.chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            for module in self.importProtoFiles(self.chooser.getSelectedFiles()):
                self.updateDescriptors(module.__name__, module)

        return


class DeserializeProtoActionListener(ActionListener):
    def __init__(self, tab, descriptor):
        self.tab = tab
        self.descriptor = descriptor

    def actionPerformed(self, event):
        content, message, info, parameter = self.tab._current

        try:
            body = content[info.getBodyOffset():].tostring()

            if parameter is not None:
                param = self.tab.helpers.getRequestParameter(
                        content, parameter.getName())

                if param is not None:
                    rules = self.tab.extender.table.getParameterRules().get(parameter.getName(), {})
                    body = param.getValue().encode('utf-8')

                    for rule in rules.get('before', []):
                        body = rule(body)

            message = parse_message(self.descriptor, body)

            self.tab.editor.setText(str(message))
            self.tab.editor.setEditable(True)
            self.tab._current = (content, message, info, parameter)

        except Exception as error:
            title = "Error parsing message as %s!" % (self.descriptor.name, )
            JOptionPane.showMessageDialog(self.tab.getUiComponent(),
                error.message, title, JOptionPane.ERROR_MESSAGE)

        return


def compile_and_import_proto(proto):
    curdir = os.path.abspath(os.curdir)
    tempdir = tempfile.mkdtemp()

    is_proto = os.path.splitext(proto.getName())[-1] == '.proto'

    if is_proto:
        try:
            os.chdir(os.path.abspath(proto.getParent()))
            subprocess.check_call(['protoc', '--python_out',
                                  tempdir, proto.getName()])
            module = proto.getName().replace('.proto', '_pb2')

        except subprocess.CalledProcessError:
            shutil.rmtree(tempdir)
            return None

        finally:
            os.chdir(curdir)

    else:
        module = proto.getName().replace('.py', '')

    try:
        if is_proto:
            os.chdir(tempdir)
        else:
            os.chdir(proto.getParent())

        sys.path.append(os.path.abspath(os.curdir))
        return importlib.import_module(module)

    finally:
        sys.path.pop()
        os.chdir(curdir)
        shutil.rmtree(tempdir)
