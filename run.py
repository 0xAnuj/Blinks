import os
import json
import httpx
import subprocess
import argparse

current_path = os.getcwd()
new_target_file_path = os.path.join(current_path, 'new_target.txt')
config_file_path = os.path.join(current_path, 'config.json')
burpconfig = f"{current_path}/burpconfig/userconfig.json"

new_extension = {
    "errors": "console",
    "extension_file": os.path.join(current_path, "scanner.py"),
    "extension_type": "python",
    "loaded": True,
    "name": "Headless Crawl and Audit",
    "output": "ui"
}

with open(config_file_path, 'r') as file:
    config_template = json.load(file)
print("[+]: Blinks config loaded.")
jython_jar_path = config_template.get("jythonPath")
burp_path = config_template.get("BurpPath")
if not jython_jar_path or not burp_path:
    print("[!]: ERROR: 'jythonPath' or 'BurpPath' is not set in config.json.")
    exit()
with open(burpconfig, 'r') as file:
    burp_config_template = json.load(file)

extension_already_present = False

if 'user_options' in burp_config_template and 'extender' in burp_config_template['user_options']:
    extensions_list = burp_config_template['user_options']['extender'].get('extensions', [])

    for ext in extensions_list:
        if ext.get('extension_file') == new_extension['extension_file'] and ext.get('name') == new_extension['name']:
            extension_already_present = True
            break

    if not extension_already_present:
        extensions_list.append(new_extension)
        burp_config_template['user_options']['extender']['extensions'] = extensions_list
else:
    burp_config_template['user_options'] = {
        'extender': {
            'extensions': [new_extension]
        }
    }

if 'python' in burp_config_template['user_options']['extender']:
    burp_config_template['user_options']['extender']['python']['location_of_jython_standalone_jar_file'] = jython_jar_path
else:
    burp_config_template['user_options']['extender']['python'] = {
        'location_of_jython_standalone_jar_file': jython_jar_path
    }


def update_burp_config():
    with open(burpconfig, 'w') as f:
            json.dump(burp_config_template, f, indent=4)    
  
def read_urls(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def is_url_alive(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url 
    try:
        response = httpx.get(url, timeout=5)
        return response.status_code
    except httpx.RequestError:
        return False

def write_alive_urls(file_path, urls):
    with open(file_path, 'w') as file:
        for url in urls:
            file.write(url + '\n')

def update_blinks_config():
    with open(config_file_path, 'w') as file:
        json.dump(config_template, file, indent=4)

def update_config(url, webhook, reporttype, crawlonly, config_template):
    parsed_url = httpx.URL(url)
    config_template["initialURL"]["url"] = url
    config_template["initialURL"]["host"] = parsed_url.host
    config_template["initialURL"]["port"] = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
    config_template["initialURL"]["protocol"] = parsed_url.scheme
    config_template["webhookurl"] = webhook if webhook else None
    if reporttype not in ["HTML", "XML"]:
        raise ValueError("Invalid report type. Only 'HTML' and 'XML' are allowed.")
    config_template["reporttype"] = reporttype
    config_template["crawlonly"] = crawlonly if crawlonly else None
    return config_template

def perform_task(url, webhook, reporttype, crawlonly, config_template):
    config_template = update_config(url, webhook, reporttype, crawlonly, config_template)

    update_blinks_config()
    
    burp_path = config_template.get("BurpPath")
    project_file = os.path.join(current_path, config_template["initialURL"]["host"])
    print("[+] Running Burp Suite")
    command = f"java -Xmx1G -Djava.awt.headless=true -jar {burp_path} --user-config-file={burpconfig} --unpause-spider-and-scanner"
    try:
        print(f"[+] Scanning {url}. See logs under ./logs")
        process = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        # print(process.stdout) 
        # print(process.stderr) 
    except subprocess.CalledProcessError as e:
        print(f"Command '{e.cmd}' returned non-zero exit status {e.returncode}.")
        print(f"Output: {e.output}")
        print(f"Error: {e.stderr}")

def main():
    print('''

    ██████╗ ██╗     ██╗███╗   ██╗██╗  ██╗███████╗
    ██╔══██╗██║     ██║████╗  ██║██║ ██╔╝██╔════╝
    ██████╔╝██║     ██║██╔██╗ ██║█████╔╝ ███████╗
    ██╔══██╗██║     ██║██║╚██╗██║██╔═██╗ ╚════██║
    ██████╔╝███████╗██║██║ ╚████║██║  ██╗███████║
    ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ v0.5b                           
    BURP HEADLESS SCANNING TOOL     Author: Punit     

    Find reports under ./reports/<Report>.XML       
    
    ''')
    parser = argparse.ArgumentParser(description='BLINKS\n v0.4b Author: Punit(0xAnuj)\n Usage: python external.py -u http://example.com -r HTML -w https:/webhook.com/webhook ')
    parser.add_argument('-u','--url', help='Single URL to process')
    parser.add_argument('-f','--file', help='File containing URLs to process')
    parser.add_argument('-w','--webhook', default=None, help='Webhook URL (default: NULL)')
    parser.add_argument('-r','--reporttype', required=True, choices=['HTML', 'XML'], help='Report type (HTML or XML)')
    parser.add_argument('--header', action='append', help='Custom headers/cookies to add to the requests (format: HeaderName:HeaderValue)')
    parser.add_argument('--crawlonly', action='store_true', help='Set crawlonly to true in config.json')
    parser.add_argument('--socks5', action='store_true', help='Use socks5 for VPN at localhost:9090')

    args = parser.parse_args()
    if args.url and args.file:
        parser.error("Specify only one of --url or --file, not both.")
    if not args.url and not args.file:
        parser.error("One of --url or --file must be provided.")

    if args.crawlonly:
        print("[+] Crawl Only Enabled, find crawled requests data under ./data/ ")

    if not extension_already_present:
        update_burp_config()
        print("Extension added to the Burp configuration.")

    if args.socks5:
        print("[+] Sock5 Enabled, Listening at 127.0.0.1:9090")
        burp_config_template['user_options']['connections']['socks_proxy']['use_proxy'] = True
        update_burp_config()
    else:
        burp_config_template['user_options']['connections']['socks_proxy']['use_proxy'] = False
        update_burp_config()  

    headers = args.header if args.header else []
    config_template["headers"] = headers
    update_blinks_config()


    urls = []
    if args.url:
        urls.append(args.url)
    elif args.file:
        urls = read_urls(args.file)

    alive_urls = []
    for url in urls:
        if is_url_alive(url):
            alive_urls.append(url)
        else:
            print(f"[!]: URL is not alive: {url}, Skipping URL!")

    write_alive_urls(new_target_file_path, alive_urls)

    new_urls = read_urls(new_target_file_path)
    for url in new_urls:
        perform_task(url, args.webhook, args.reporttype, args.crawlonly, config_template)

if __name__ == '__main__':
    main()
