<h1 align="center">
  <br>
  <a href="https://github.com/0xAnuj/Blinks"><img src="https://github.com/user-attachments/assets/256b8c0a-4358-4787-8d41-39a13b2b95f8" alt="Blinks"></a><br>
  Blinks <br>
</h1>

<h4 align="center">Blinks: Burp Headless Scanning Tool</h4>

Blinks is a powerful Burp Suite extension that automates active scanning with Burp Suite Pro and enhances its functionality. With the integration of webhooks, this tool sends real-time updates whenever a new issue is identified, directly to your preferred endpoint. No more waiting for final reports – you get instant, actionable insights! 🛠️
![blinks_terminal](https://github.com/user-attachments/assets/f986932c-455b-4fdc-aeb6-36b339c92704)

## Usage
> Note: Blinks only works with Licensed Burp Suite Professional, Make sure you set up your Burp Suite License before setting up Blinks.

#### 1. Setup Config
Add the path for the Burp Suite Pro JAR file and Jython.jar file inside `config.json`.
```json
{
    "initialURL": {
        "url": "https://example.com",
        "host": "example.com",
        "port": 443,
        "protocol": "https"
    },
    "webhookurl": null,
    "crawlonly": null,
    "proxyonly": null,
    "reporttype": "HTML",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "headers": [],
    "staticFileExt": [
        "css",
        "js",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "svg"
    ],
    "exclusions": [
        "/exclude-this-path",
        "/another-exclude-path"
    ],
    "BurpPath": "BURP PATH HERE",   <--- Add Burp.jar file path 
    "jythonPath": "JYTHON PATH HERE"   <--- Add Jython.jar file path 
}
```
#### 2. Run Blinks
```
Usage: python3 run.py -u https://example.com -r HTML -w https://webhook.url/endpoint

Arguments:

  -h, --help            show this help message and exit
  -u, --url             Single URL to process 
  -f, --file            File containing URLs to process 
  -w, --webhook         Webhook URL (default: NULL)    
  -r, --reporttype      Report type (HTML or XML)
  --header              Custom headers/cookies to add to the requests (format: HeaderName:HeaderValue), reuse the argument for multiple headers
  --crawlonly           Perfom crawl only scan, it will save all crawled requests under ./data/
  --socks5              Use socks5 for VPN at localhost:9090
```

## Features

- Blinksless Operation
**Blinks** runs Burp Suite scans in a Blinksless mode, allowing for automation without the need for a graphical user interface (GUI). This makes it ideal for integration into pipelines or remote servers.
- Single and Batch URL Processing
  - **Single URL Processing:** Easily scan a single target URL.
  - **Batch URL Processing:** Supply a file containing multiple URLs, and Blinks will process each one sequentially, making it efficient for large-scale assessments.

- Customizable Report Generation
  - **HTML Reports:** Easy-to-read format for human review.
  - **XML Reports:** Structured format for machine processing or further analysis.

- Webhook Integration for Real-Time Notifications
**Blinks** supports webhook integration, allowing you to send scan results directly to a specified URL. This feature is particularly useful for real-time monitoring and integration with alerting systems.

- Crawl Only Mode
If you only need to map out the structure of a web application without performing a full security scan, you can use the **Crawl Only** mode. This limits the scan to discovering URLs and resources.

- SOCKS5 Proxy Support
For enhanced security during scans, especially in environments requiring VPN connections, **Blinks** includes support for a SOCKS5 proxy running at `localhost:9090`.

- Flexible Configuration
**Blinks** provides a JSON-based configuration file (`config.json`) that allows you to customize various aspects of the scan.

## Attach More Extensions

You can attach more Burp extensions by modifying the `./burpconfig/userconfig.json` file. For example:

```json
<SNIP>
"extender": {
    "extensions": [
        {
            "errors": "console",
            "extension_file": "EXTENSION_PATH",
            "extension_type": "python/java/ruby",
            "loaded": true,
            "name": "Extension Name",
            "output": "ui"
        }
    ]
}
<SNIP>
```
This configuration allows you to load and manage multiple Burp extensions, each defined by its file path, type, and other properties. Simply edit the extension_file path and other fields as necessary to load additional extensions.

## License

This project is licensed under the **[GNU Affero General Public License v3.0 (AGPL-3.0)](https://github.com/0xAnuj/Blinks/blob/main/LICENSE)**.


