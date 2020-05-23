# Burp DoH Decoder

Decodes DNS messages from HTTP(S) requests and responses with the MIME type `application/dns-message`

## Getting Started

### Install Burp DoH Decoder
1. Go to your desired extension installation directory and run the following commands. 
    ```sh
    git clone https://github.com/DNS-Privacy-Security/burp-doh-decoder.git
    pip install -r burp-doh-decoder/requirements.txt --target=Lib
    ```

2. If not already installed, download the standalone Jython JAR file from https://www.jython.org/download into the same directory and define the file location in Burp:\
Extender ➡ Options ➡ Python Environment ➡ Location of Jython standalone JAR file.\
If you installed Jython in a different directory, you must also configure the module loading folder by selecting the `Lib` folder.
3. Add Burp DoH Decoder to the Burp extensions:\
Extender ➡ Extensions ➡ Add\
Configure the Extension Details and press Next button
    * Extension type: Python
    * Extension file: `<path/of/burp-doh-decoder.py>`

4. The Burp DoH Decoder is now installed and no errors should be visible on the Errors tab

## Documentation

You can find the [Documentation](docs/DOCUMENTATION.md) in the docs folder.

## Screenshots

### DoH Request

![DoH Request](img/doh-request.png "DoH request with Burp DoH Decoder")

### DoH Response

![DoH Request](img/doh-response.png "DoH response with Burp DoH Decoder")
