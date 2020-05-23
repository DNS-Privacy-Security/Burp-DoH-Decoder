<a name=".burp-doh-decoder"></a>
## burp-doh-decoder

<a name=".burp-doh-decoder.BurpExtender"></a>
### BurpExtender

```python
class BurpExtender(IBurpExtender,  IMessageEditorTabFactory)
```

Implements IBurpExtender for registerExtenderCallbacks and IMessageEditorTabFactory to access createNewInstance

**Arguments**:

- `IBurpExtender` - All extensions must implement this interface. Implementations must be called BurpExtender, in the package burp, must be declared public, and must provide a default (public, no-argument) constructor.
- `IMessageEditorTabFactory` - Extensions can implement this interface and then call IBurpExtenderCallbacks.registerMessageEditorTabFactory() to register a factory for custom message editor tabs. This allows extensions to provide custom rendering or editing of HTTP messages, within Burp's own HTTP editor.

<a name=".burp-doh-decoder.BurpExtender.registerExtenderCallbacks"></a>
#### registerExtenderCallbacks

```python
 | registerExtenderCallbacks(callbacks)
```

This method is invoked when the extension is loaded. It registers an instance of the IBurpExtenderCallbacks interface, providing methods that may be invoked by the extension to perform various actions.

**Arguments**:

- `callbacks` _IBurpExtenderCallbacks_ - Instance of the IBurpExtenderCallbacks interface

<a name=".burp-doh-decoder.BurpExtender.createNewInstance"></a>
#### createNewInstance

```python
 | createNewInstance(controller, editable)
```

Burp will call this method once for each HTTP message editor, and the factory should provide a new instance of an IMessageEditorTab object.

**Arguments**:

- `controller` _IMessageEditorController_ - An IMessageEditorController object, which the new tab can query to retrieve details about the currently displayed message. This may be null for extension-invoked message editors where the extension has not provided an editor controller.
- `editable` _bool_ - Indicates whether the hosting editor is editable or read-only.
  

**Returns**:

- `IMessageEditorTab` - A new IMessageEditorTab object for use within the message editor.

<a name=".burp-doh-decoder.DisplayValues"></a>
### DisplayValues

```python
class DisplayValues(IMessageEditorTab)
```

Implements IMessageEditorTab to create a message tab, and controls how http messages are pocessed

**Arguments**:

- `IMessageEditorTab` - Extensions that register an IMessageEditorTabFactory must return instances of this interface, which Burp will use to create custom tabs within its HTTP message editors.

<a name=".burp-doh-decoder.DisplayValues.__init__"></a>
#### \_\_init\_\_

```python
 | __init__(extender, controller, editable)
```

Burp will call this method once for each HTTP message editor, and the factory should provide a new instance of an IMessageEditorTab object.

**Arguments**:

- `extender` _BurpExtender_ - The BurpExtender that implements IBurpExtender for registerExtenderCallbacks and IMessageEditorTabFactory to access createNewInstance
- `controller` _IMessageEditorController_ - An IMessageEditorController object, which the new tab can query to retrieve details about the currently displayed message
- `editable` _bool_ - Indicates whether the hosting editor is editable or read-only.

<a name=".burp-doh-decoder.DisplayValues.getUiComponent"></a>
#### getUiComponent

```python
 | getUiComponent()
```

This method returns the component that should be used as the contents of the custom tab when it is displayed.

**Returns**:

- `java.awt.Component` - Returns the Burp component for the custom tab

<a name=".burp-doh-decoder.DisplayValues.getTabCaption"></a>
#### getTabCaption

```python
 | getTabCaption()
```

This method returns the caption that should appear on the custom tab when it is displayed.

**Returns**:

- `str` - Returns the Burp tab caption

<a name=".burp-doh-decoder.DisplayValues.isEnabled"></a>
#### isEnabled

```python
 | isEnabled(content, isRequest)
```

The hosting editor will invoke this method before it displays a new HTTP message, so that the custom tab can indicate whether it should be enabled for that message.

**Arguments**:

- `content` _str_ - The message that is about to be displayed, or a zero-length array if the existing message is to be cleared.
- `isRequest` _bool_ - Indicates whether the message is a request or a response.
  

**Returns**:

- `bool` - The method should return true if the custom tab is able to handle the specified message, and so will be displayed within the editor. Otherwise, the tab will be hidden while this message is displayed.

<a name=".burp-doh-decoder.DisplayValues.setMessage"></a>
#### setMessage

```python
 | setMessage(content, isRequest)
```

The hosting editor will invoke this method to display a new message or to clear the existing message. This method will only be called with a new message if the tab has already returned true to a call to isEnabled() with the same message details.

**Arguments**:

- `content` _str_ - The message that is about to be displayed, or a zero-length array if the existing message is to be cleared.
- `isRequest` _bool_ - Indicates whether the message is a request or a response.

<a name=".burp-doh-decoder.DisplayValues.getMessage"></a>
#### getMessage

```python
 | getMessage()
```

This method returns the currently displayed message.

**Returns**:

- `str` - The currently displayed message.

<a name=".burp-doh-decoder.DisplayValues.isModified"></a>
#### isModified

```python
 | isModified()
```

This method is used to determine whether the currently displayed message has been modified by the user. The hosting editor will always call getMessage() before calling this method, so any pending edits should be completed within getMessage().

**Returns**:

- `bool` - The method should return true if the user has modified the current message since it was first displayed.

