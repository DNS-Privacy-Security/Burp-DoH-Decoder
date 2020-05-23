import sys
import dnslib
import base64
from burp import IBurpExtender
from burp import IMessageEditorTab
from burp import IMessageEditorTabFactory


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    """Implements IBurpExtender for registerExtenderCallbacks and IMessageEditorTabFactory to access createNewInstance

    Arguments:
        IBurpExtender -- All extensions must implement this interface. Implementations must be called BurpExtender, in the package burp, must be declared public, and must provide a default (public, no-argument) constructor.
        IMessageEditorTabFactory -- Extensions can implement this interface and then call IBurpExtenderCallbacks.registerMessageEditorTabFactory() to register a factory for custom message editor tabs. This allows extensions to provide custom rendering or editing of HTTP messages, within Burp's own HTTP editor.
    """

    def registerExtenderCallbacks(self, callbacks):
        """This method is invoked when the extension is loaded. It registers an instance of the IBurpExtenderCallbacks interface, providing methods that may be invoked by the extension to perform various actions.

        Arguments:
            callbacks {IBurpExtenderCallbacks} -- Instance of the IBurpExtenderCallbacks interface
        """
        callbacks.setExtensionName("DoH DNS-Message Decoder")
        callbacks.registerMessageEditorTabFactory(self)

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        return

    def createNewInstance(self, controller, editable):
        """Burp will call this method once for each HTTP message editor, and the factory should provide a new instance of an IMessageEditorTab object.

        Arguments:
            controller {IMessageEditorController} -- An IMessageEditorController object, which the new tab can query to retrieve details about the currently displayed message. This may be null for extension-invoked message editors where the extension has not provided an editor controller.
            editable {bool} -- Indicates whether the hosting editor is editable or read-only.

        Returns:
            IMessageEditorTab -- A new IMessageEditorTab object for use within the message editor.
        """
        return DisplayValues(self, controller, editable)


class DisplayValues(IMessageEditorTab):
    """Implements IMessageEditorTab to create a message tab, and controls how http messages are pocessed

    Arguments:
        IMessageEditorTab -- Extensions that register an IMessageEditorTabFactory must return instances of this interface, which Burp will use to create custom tabs within its HTTP message editors.
    """

    def __init__(self, extender, controller, editable):
        """Burp will call this method once for each HTTP message editor, and the factory should provide a new instance of an IMessageEditorTab object.

        Arguments:
            extender {BurpExtender} -- The BurpExtender that implements IBurpExtender for registerExtenderCallbacks and IMessageEditorTabFactory to access createNewInstance
            controller {IMessageEditorController} -- An IMessageEditorController object, which the new tab can query to retrieve details about the currently displayed message
            editable {bool} -- Indicates whether the hosting editor is editable or read-only.
        """
        self._txtInput = extender._callbacks.createTextEditor()
        self._extender = extender
        self._message = None

    def getUiComponent(self):
        """This method returns the component that should be used as the contents of the custom tab when it is displayed.

        Returns:
            java.awt.Component -- Returns the Burp component for the custom tab
        """
        return self._txtInput.getComponent()

    def getTabCaption(self):
        """This method returns the caption that should appear on the custom tab when it is displayed.

        Returns:
            str -- Returns the Burp tab caption
        """
        return 'DNS-Message'

    def isEnabled(self, content, isRequest):
        """The hosting editor will invoke this method before it displays a new HTTP message, so that the custom tab can indicate whether it should be enabled for that message.

        Arguments:
            content {str} -- The message that is about to be displayed, or a zero-length array if the existing message is to be cleared.
            isRequest {bool} -- Indicates whether the message is a request or a response.

        Returns:
            bool -- The method should return true if the custom tab is able to handle the specified message, and so will be displayed within the editor. Otherwise, the tab will be hidden while this message is displayed.
        """
        requestInfo = self._extender._helpers.analyzeRequest(content)

        headers = requestInfo.getHeaders()
        doh_headers = [
            'accept: application/dns-message',
            'content-type: application/dns-message'
        ]

        if any(elem.lower() in doh_headers for elem in headers):
            return True

        return False

    def setMessage(self, content, isRequest):
        """The hosting editor will invoke this method to display a new message or to clear the existing message. This method will only be called with a new message if the tab has already returned true to a call to isEnabled() with the same message details.

        Arguments:
            content {str} -- The message that is about to be displayed, or a zero-length array if the existing message is to be cleared.
            isRequest {bool} -- Indicates whether the message is a request or a response.
        """
        self._txtInput.setEditable(False)

        requestInfo = self._extender._helpers.analyzeRequest(content)
        headers = requestInfo.getHeaders()

        if requestInfo.getMethod() == 'GET' in headers:
            for param in requestInfo.getParameters():
                if param.getName().lower() == 'dns':
                    bodyBytes = base64.b64decode(param.getValue)
        else:
            bodyOffset = requestInfo.getBodyOffset()
            bodyBytes = content[bodyOffset:]

        try:
            dns_record = dnslib.DNSRecord()
            dns_packet = dns_record.parse(bodyBytes)
        except dnslib.dns.DNSError:
            return

        message_lines = str(dns_packet).splitlines()
        for i in range(len(message_lines)):
            if message_lines[i].endswith('SECTION:'):
                message_lines[i] = '\n' + message_lines[i]

        message_size = len(bodyBytes)
        direction = 'sent' if isRequest else 'rcvd'

        message_lines.append(
            '\n;; MSG SIZE  ' +
            direction + ': ' + str(message_size)
        )
        self._message = '\n'.join(message_lines)
        self._txtInput.setText(self._message)

    def getMessage(self):
        """This method returns the currently displayed message.

        Returns:
            str -- The currently displayed message.
        """
        return self._txtInput.getText()

    def isModified(self):
        """This method is used to determine whether the currently displayed message has been modified by the user. The hosting editor will always call getMessage() before calling this method, so any pending edits should be completed within getMessage().

        Returns:
            bool -- The method should return true if the user has modified the current message since it was first displayed.
        """
        return not self._txtInput.getText().equals(self._message)
