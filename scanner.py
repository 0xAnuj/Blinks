# Blinks - Burp Headless Scanning Tool [v0.5b (14-Aug-2024)]
# Author: Punit (0xAnuj)
# Linkedin: https://www.linkedin.com/in/0xanuj/
from burp import IBurpExtender, IScannerListener, IHttpListener, IScanIssue, IScanQueueItem
from java.io import BufferedReader, FileReader, File, PrintWriter, FileWriter, InputStreamReader, OutputStream
from java.net import URL, HttpURLConnection, URLDecoder
import datetime
from threading import Thread, Event, Lock
import time
import re,os
import json

class BurpExtender(IBurpExtender, IScannerListener, IHttpListener, IScanQueueItem):

    isActiveScanActive = False  
    INACTIVITY_THRESHOLD = 10  
    #TIMEOUT_SECONDS = 10 

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._scanQueueItems = []
        self._lastRequestTime = datetime.datetime.now()
        self._inactivity_event = Event()
        self._lock = Lock()


        callbacks.setExtensionName("Blinks")
        callbacks.registerScannerListener(self)
        callbacks.registerHttpListener(self)
        self.isActiveScanActive = False
        self.current_dir = os.getcwd()
        self.extConfig = self.load_config("{}/config.json".format(self.current_dir))
        self.log_file = "{}/logs/scan_status_{}.log".format(self.current_dir,self.extConfig["initialURL"]["host"])
        self.crawled_requests_file = "{}/data/crawled_data_{}.txt".format(self.current_dir,self.extConfig["initialURL"]["host"])
        self.active_requests_file = "{}/data/active_check_{}.txt".format(self.current_dir,self.extConfig["initialURL"]["host"])
        self.proxy_requests_file = "{}/data/proxy_data_{}.txt".format(self.current_dir,self.extConfig["initialURL"]["host"])
        self.report_name = self.extConfig["initialURL"]["host"]
        self.reporttype = self.extConfig["reporttype"]
        self.webhookURL = self.extConfig["webhookurl"]
        self.crawlonly = self.extConfig["crawlonly"]
        self.proxyonly = self.extConfig["proxyonly"]
        self.headers = self.extConfig['headers']
        self.log_message(self.headers)
        self.log_message("Extension Loaded Successfully")
        self.log_message("Blinks v0.5b  Author: Punit")
        self.run_headless_scan()


    def run_headless_scan(self):
        self.log_message("Running Headless Crawl and Audit")
        try:
            iurl = self.extConfig["initialURL"]["url"]
            self.log_message("Targets: " + str(iurl))
            self.log_message("Starting spider for: " + iurl)
            self.scan_url(iurl)
            with open(self.crawled_requests_file, "a") as f:
                f.write("\n===\n")
            with open(self.active_requests_file, "a") as f:
                f.write("\n===\n")
            Thread(target=self.monitor_file_size).start()

        except Exception as e:
            self.log_message("Error running headless crawl and audit: " + str(e), error=True)

    def process_requests(self,input_filename, output_filename):
        try:
            try:
                with open(input_filename, 'r') as file:
                    content = file.read()
                    requests = content.split('===\n')
                    requests = [request.strip() for request in requests if request.strip()]
            except Exception as e:
                self.log_message("Error reading from file: {}. Error: {}".format(input_filename, str(e)))
                return

            seen_requests = set()
            filtered_requests = []

            # Process and filter requests
            for request in requests:
                try:
                    request_lines = request.replace('\r\n', '\n').split('\n')
                    
                    try:
                        method, url, _ = request_lines[0].split()
                    except ValueError as e:
                        self.log_message("Error parsing request line: {}. Error: {}".format(request_lines[0], str(e)))
                        continue

                    try:
                        endpoint = url.split('?')[0]
                        query_string = url.split('?')[1] if '?' in url else ''
                        url_params_keys = set(URLDecoder.decode(query_string, "UTF-8").split('&'))
                        url_params_keys = set(param.split('=')[0] for param in url_params_keys if param)
                    except Exception as e:
                        self.log_message("Error parsing URL: {}. Error: {}".format(url, str(e)))
                        continue

                    body_params_keys = set()

                    if method == 'POST':
                        try:
                            body_start = next((i for i in range(len(request_lines)) if not request_lines[i].strip()), None)
                            if body_start is not None and (body_start + 1) < len(request_lines):
                                body_content = '\n'.join(request_lines[body_start + 1:])

                                headers = {}
                                for line in request_lines[1:body_start]:
                                    if ': ' in line:
                                        key, value = line.split(': ', 1)
                                        headers[key.lower()] = value

                                content_type = headers.get("content-type", "")

                                if "application/x-www-form-urlencoded" in content_type:
                                    body_params_keys = set(URLDecoder.decode(body_content, "UTF-8").split('&'))
                                    body_params_keys = set(param.split('=')[0] for param in body_params_keys if param)
                                elif "application/json" in content_type:
                                    try:
                                        body_params = json.loads(body_content)
                                        body_params_keys = set(body_params.keys())
                                    except ValueError as e:
                                        self.log_message("Invalid JSON in request body: {}. Error: {}".format(body_content[:50], str(e)))
                                elif "multipart/form-data" in content_type:
                                    boundary = content_type.split("boundary=")[1]
                                    body_content = '\n'.join(request_lines[body_start + 1:])
                                    body_content = body_content.replace('\n', '\r\n').encode('utf-8')
                                    multipart_data = BytesParser().parsebytes(body_content, boundary=boundary.encode('utf-8'))

                                    for part in multipart_data.walk():
                                        content_disposition = part.get("Content-Disposition", "")
                                        if "form-data" in content_disposition:
                                            name = content_disposition.split("name=")[1].strip('"')
                                            body_params_keys.add(name)        

                        except Exception as e:
                            self.log_message("Error parsing request body: {}. Error: {}".format(request[:50], str(e)))

                    all_param_keys = url_params_keys.union(body_params_keys)

                    self.log_message("Method: {}, Endpoint: {}, Params: {}".format(method, endpoint, all_param_keys))

                    unique_key = (method, endpoint, frozenset(all_param_keys))

                    if unique_key not in seen_requests:
                        seen_requests.add(unique_key)
                        filtered_requests.append(request)
                    else:
                        self.log_message("Duplicate found: {} {} with params {}".format(method, endpoint, all_param_keys))

                except Exception as e:
                    self.log_message("Error processing request: {}. Error: {}".format(request[:50], str(e)))

            try:
                with open(output_filename, 'w') as file:
                    for request in filtered_requests:
                        try:
                            file.write(request + '\n===\n')
                        except Exception as e:
                            self.log_message("Error writing request to file: {}. Error: {}".format(request[:50], str(e)))
            except Exception as e:
                self.log_message("Error writing to file: {}. Error: {}".format(output_filename, str(e)))

            self.log_message("Filtered requests have been written to {}".format(output_filename))
            self.log_message("Original request count: {}".format(len(requests)))
            self.log_message("Filtered request count: {}".format(len(filtered_requests)))

        except Exception as e:
            self.log_message("Unexpected error in process_requests: {}".format(str(e)))


    def monitor_file_size(self):
        import os, time
        last_size = -1
        stable_time = None
        self.log_message("Inside Monitor function last size :{} and Stable_time: {} ".format(last_size, stable_time))
        if self.isActiveScanActive:
            file = self.active_requests_file
        else:
            file =self.crawled_requests_file

        while True:
            try:
                current_size = os.path.getsize(file)
                if current_size == last_size:
                    if stable_time is None:
                        stable_time = time.time()  
                    elif time.time() - stable_time > 22:  
                        self.log_message("Crawled Finished!.")
                        self.process_requests(self.crawled_requests_file,self.crawled_requests_file)
                        if self.crawlonly == True:
                            self.log_message("scanning Finished!")
                            self._callbacks.exitSuite(False)
                        else:
                            self.isActiveScanActive = True
                            Thread(target=self.monitor_file_size_active).start()
                              # Start monitoring scan status
                            self.log_message(self.isActiveScanActive)
                            self.ActiveScanFileRun(self.isActiveScanActive)
                            break 
                else:
                    stable_time = None  
                last_size = current_size
            except FileNotFoundError:
                self.log_message("Crawled requests file not found.")
            time.sleep(1) 

    def monitor_scan_status(self,scan_queue_item):
        #need to work on this logic
          if self.isActiveScanActive:
                try:
                    while True:
                        status = self.scan_queue_item.getStatus()
                        self.log_message("Scan Status: {}".format(status))
                        time.sleep(1)  # Check every 10 seconds
                except Exception as e:
                    self.log_message("ERROR IN MONITOR: {}".format(e))

    def monitor_file_size_active(self):
        import os, time
        last_size = -1
        stable_time = None
        self.log_message("Active: Inside Monitor function last size :{} and Stable_time: {} ".format(last_size, stable_time))
        while True:
            if self.isActiveScanActive:
                try:
                    current_size = os.path.getsize(self.active_requests_file)
                    if current_size == last_size:
                        if stable_time is None:
                            stable_time = time.time()  
                        elif time.time() - stable_time > 120:
                            self.log_message("Active Scan done.")
                            self.log_message(self.isActiveScanActive)
                            self.report_file = "{}/reports/Final_scan_report_{}_{}.{}".format(self.current_dir,self.report_name,datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"),self.reporttype)
                            self.generate_report(self.reporttype, self.report_file)
                            self.reset_data_files()
                            time.sleep(5)
                            self.log_message("scanning Finished!")
                            self._callbacks.exitSuite(False)
                            break  
                    else:
                        stable_time = None  
                    last_size = current_size
                except FileNotFoundError:
                    self.log_message("Active requests file not found.")
            time.sleep(1) 

    def reset_data_files(self):
         if self.isActiveScanActive:
            try: 
                with open(self.active_requests_file, "w") as f:
                    f.write("")
                with open(self.crawled_requests_file, "w") as f:
                    f.write("")    
                return
            except Exception as e:
                self.log_message(e)

    def scan_url(self, url):
        try:
            parsed_url = URL(url)
            self.log_message("Parsed URL: {}".format(parsed_url))
            
            protocol = parsed_url.getProtocol()
            hostname = parsed_url.getHost()
            
            hostname_segments = hostname.split('.')
            
            # Check if hostname is a top-level domain (two segments)
            if len(hostname_segments) == 2:
                # Construct www. subdomain with the same protocol
                www_url = "{}://www.{}".format(protocol, hostname)
                parsed_url = URL(www_url)
                if not self._callbacks.isInScope(parsed_url):
                    self._callbacks.includeInScope(parsed_url)
                    self.log_message("Added www subdomain to scope: {}".format(parsed_url))
            
            if not self._callbacks.isInScope(parsed_url):
                self._callbacks.includeInScope(parsed_url)
                self.log_message("Added URL to scope: {}".format(parsed_url))
            time.sleep(5)
            
            self._callbacks.sendToSpider(parsed_url)
            self._lastRequestTime = datetime.datetime.now()
            self.log_message("Starting spider on {} at {}".format(url, self._lastRequestTime))

        except Exception as e:
            self.log_message("Error scanning URL {}: {}".format(url, str(e)), error=True)



    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
            if self.isActiveScanActive:
                request = self._helpers.bytesToString(messageInfo.getRequest())
                with open(self.active_requests_file, "a") as f:
                    f.write("\n===\n")
                return

            self.log_message("Processing HTTP message: toolFlag={}, messageIsRequest={}".format(toolFlag, messageIsRequest))
            
            if toolFlag == self._callbacks.TOOL_SPIDER or toolFlag == self._callbacks.TOOL_SCANNER:
                if messageIsRequest:
                    requestInfo = self._helpers.analyzeRequest(messageInfo)
                    headers = list(requestInfo.getHeaders())
                    if self.headers:
                        for header in self.headers:
                            headers.append(header)
                    bodyBytes = messageInfo.getRequest()[requestInfo.getBodyOffset():]
                    newRequest = self._helpers.buildHttpMessage(headers, bodyBytes)
                    messageInfo.setRequest(newRequest)

                url = self._helpers.analyzeRequest(messageInfo).getUrl()
                self.log_message("Crawled URL: {}".format(url))
                if self._callbacks.isInScope(url) and not self.is_static_file(url.getPath()):
                    self.save_and_scan_request(messageInfo)
            else:
                self.log_message("Ignoring message with toolFlag: {}, messageIsRequest: {}".format(toolFlag, messageIsRequest))

    def save_and_scan_request(self, messageInfo):
        try:
            request = self._helpers.bytesToString(messageInfo.getRequest())
            with open(self.crawled_requests_file, "a") as f:
                f.write(request + "\n===\n")
        except Exception as e:
            self.log_message("Error saving and scanning request: {}".format(str(e)), error=True)

    def ActiveScanFileRun(self, isActiveScanActive):
        if not isActiveScanActive:
            return
        self.isActiveScanActive = True
        self.log_message("ActiveScanFileRun Active Status: {}".format(self.isActiveScanActive))
        seen_requests = set()
        while True:
            try:
                with open(self.crawled_requests_file, "r") as f:
                    requests = f.read().split("\n===\n")
                    for request in requests:
                        if request.strip() and request not in seen_requests:
                            self.log_message("New request found, sending to scanner")
                            seen_requests.add(request)
                            self.send_to_scanner(request)
                time.sleep(1)
            except Exception as e:
                self.log_message("Error reading crawled requests file: {}".format(str(e)), error=True)

    def send_to_scanner(self, request):
        try:
            host = self.extConfig["initialURL"]["host"]
            port = self.extConfig["initialURL"]["port"]
            protocol = self.extConfig["initialURL"]["protocol"]

            httpService = self._helpers.buildHttpService(host, port, protocol == "https")
            self.log_message("Sending request to scanner")
            self._callbacks.doActiveScan(
                httpService.getHost(),
                httpService.getPort(),
                protocol == "https",
                self._helpers.stringToBytes(request)
            )
        except Exception as e:
            self.log_message("Error sending to scanner: {}".format(str(e)), error=True)


    def log_message(self, message, error=False):
        try:
            with open(self.log_file, "a") as log:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log.write("[{}] {}{}\n".format(
                    timestamp,
                    "ERROR: " if error else "",
                    message
                ))
                print("[{}] {}{}".format(
                    timestamp,
                    "ERROR: " if error else "",
                    message
                ))
                self._callbacks.printOutput("[{}] {}{}".format(
                    timestamp,
                    "ERROR: " if error else "",
                    message
                ))
        except Exception as e:
            print("Failed to log message: {}".format(str(e)))

    def generate_report(self, reportType, reportFile):
        try:
            issues = self._callbacks.getScanIssues(None)  
            if issues:
                self.log_message("Number of issues found: {}".format(len(issues)))
                file = File(reportFile)
                self._callbacks.generateScanReport(reportType, issues, file)
                self.log_message("Report saved to {}".format(reportFile))
            else:
                self.log_message("No issues found to report.")
        except Exception as e:
            self.log_message("Error saving report: {}".format(str(e)), error=True)

    def load_config(self, config_file):
        
        with open(config_file, 'r') as file:
            config = json.load(file)
        return config

    def is_static_file(self, path):
        skip_files = ["/favicon.ico", "/robots.txt"] #need to work on this logic
        if path in skip_files:
            return True
        for ext in self.extConfig.get("staticFileExt", []):
            if path.endswith(".{}".format(ext)):
                return True
        return False
    # For ongoing reports
    def newScanIssue(self, issue):
        self.log_message("New scan issue identified: {}".format(issue.getIssueName()))

        try:
            issue_details = {
                "issue_name": str(issue.getIssueName()),
                "severity": str(issue.getSeverity()),
                "confidence": str(issue.getConfidence()),
                "url": str(issue.getUrl()),
                "issue_detail": issue.getIssueDetail() and str(issue.getIssueDetail()),
                "issue_background": issue.getIssueBackground() and str(issue.getIssueBackground()),
                "remediation_detail": issue.getRemediationDetail() and str(issue.getRemediationDetail()),
                "remediation_background": issue.getRemediationBackground() and str(issue.getRemediationBackground()),
                "host": str(issue.getHttpMessages()[0].getHttpService().getHost()),
                "port": issue.getHttpMessages()[0].getHttpService().getPort(),
                "protocol": "https" if issue.getHttpMessages()[0].getHttpService().getProtocol() else "http"
            }

            for i, http_message in enumerate(issue.getHttpMessages()):
                request_info = self._helpers.analyzeRequest(http_message)
                response_info = self._helpers.analyzeResponse(http_message.getResponse())
                
                request_headers = [str(header) for header in request_info.getHeaders()]
                request_body = str(self._helpers.bytesToString(http_message.getRequest())[request_info.getBodyOffset():])
                
                response_headers = [str(header) for header in response_info.getHeaders()]
                response_body = str(self._helpers.bytesToString(http_message.getResponse())[response_info.getBodyOffset():])

                issue_details["request_{}_headers".format(i+1)] = request_headers
                issue_details["request_{}_body".format(i+1)] = request_body
                issue_details["response_{}_headers".format(i+1)] = response_headers
                issue_details["response_{}_body".format(i+1)] = response_body
            json_data = json.dumps(issue_details, ensure_ascii=False)

            json_data = json_data.replace("\\/", "/")
            self.send_issue_to_webhook(json_data)
            self.report_file = "{}/reports/SCAN_PENDING_issues_report_{}.{}".format(self.current_dir,self.report_name,self.reporttype)
            self.generate_report(self.reporttype, self.report_file)    


        except Exception as e:
            self.log_message("ERROR: Error processing issue details: {}".format(str(e)), error=True)

    def send_issue_to_webhook(self, json_data):
        try:
            webhook_url = self.webhookURL 
            if webhook_url == None:
                return
            url = URL(webhook_url)
            conn = url.openConnection()
            conn.setRequestMethod("POST")
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setDoOutput(True)

            # Write the JSON data to the output stream
            output_stream = conn.getOutputStream()
            output_stream.write(json_data.encode('utf-8'))
            output_stream.close()

            response_code = conn.getResponseCode()
            if response_code == HttpURLConnection.HTTP_OK:
                self.log_message("Issue successfully sent to webhook.")
            else:
                self.log_message("Failed to send issue to webhook. Status code: {}".format(response_code), error=True)

            conn.disconnect()

        except Exception as e:
            self.log_message("Error sending issue to webhook: {}".format(str(e)), error=True)



