<h1 align="center">
    headerpwn
    <br>
</h1>

<h4 align="center">A fuzzer for analyzing how servers respond to different HTTP headers.</h4>

<p align="center">
  <a href="#install">🏗️ Install</a>
  <a href="#usage">⛏️ Usage</a>
  <a href="#proxying-requests-through-burp-suite">📡 Proxying HTTP Requests</a>
  <a href="#credits">📜 Credits</a>
  <br>
</p>

<p align="center">
  <img src="https://github.com/devanshbatham/headerpwn/blob/main/static/banner.png?raw=true" alt="headerpwn" />
</p>

## Install
To install `headerpwn`, run the following command:

```sh
go install github.com/tucommenceapousser/headerpwn@v0.0.3
```

## Usage
`headerpwn` allows you to test various headers on a target URL and analyze the responses. Here's how to use the tool:

1. **Provide the target URL** using the `-url` flag.
2. **Create a file containing the headers** you want to test, one header per line. Use the `-headers` flag to specify the path to this file.
3. **Specify the Request Catcher URL** with the `-catcher` flag to monitor for XSS attacks.

Example usage:

```sh
./headerpwn -url https://www.alsetex.fr -headers header-catch.txt -catcher https://a47da360-e441-41d7-a30b-2c0e4b8e8a34-00-1j353q5zm79dz.pike.replit.dev/__xss_detected__ -output xss_results.txt
```

- **Format of `header-catch.txt`** should be like below:

```plaintext
Proxy-Authenticate: foobar
Proxy-Authentication-Required: foobar
Proxy-Authorization: foobar
Proxy-Connection: foobar
Proxy-Host: foobar
Proxy-Http: foobar
```

## Viewing Results
To view the results of XSS detections, you can access the Request Catcher web interface at:

[https://a47da360-e441-41d7-a30b-2c0e4b8e8a34-00-1j353q5zm79dz.pike.replit.dev/ui](https://a47da360-e441-41d7-a30b-2c0e4b8e8a34-00-1j353q5zm79dz.pike.replit.dev/ui)

This page will show you the requests that were logged and indicate if any XSS attacks were detected.

## Proxying Requests through Burp Suite
To proxy requests through Burp Suite, follow these steps:

1. **Export Burp's Certificate**:
    - In Burp Suite, go to the "Proxy" tab.
    - Under the "Proxy Listeners" section, select the listener configured for `127.0.0.1:8080`.
    - Click on the "Import/Export CA Certificate" button.
    - In the certificate window, click "Export Certificate" and save the certificate file (e.g., burp.der).

2. **Install Burp's Certificate**:
    - Install the exported certificate as a trusted certificate on your system. 
    - **Windows**: Double-click the .cer file and follow the prompts to install it in the "Trusted Root Certification Authorities" store.
    - **macOS**: Double-click the .cer file and add it to the "Keychain Access" application in the "System" keychain.
    - **Linux**: Copy the certificate to a trusted certificate location and configure your system to trust it.

Once configured, you can run:

```sh
headerpwn -url https://example.com -headers my_headers.txt -proxy 127.0.0.1:8080
```

## Credits
The `headers.txt` file is compiled from various sources, including the [Seclists project](https://github.com/danielmiessler/SecLists). These headers are used for testing purposes and provide a variety of scenarios for analyzing how servers respond to different headers.
