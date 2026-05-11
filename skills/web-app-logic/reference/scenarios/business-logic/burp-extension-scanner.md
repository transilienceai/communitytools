# Burp Extension — Business Logic Scanner

## When this applies

- You want passive/active scanning for client-side price/quantity/role parameters.
- You're auditing a large attack surface and want auto-flagging of suspicious parameter names.
- You need a starting point to write custom Burp extensions for logic-flaw detection.

## Technique

Custom Burp extension that:
1. Passively flags parameter names matching `price|cost|amount|total`.
2. Actively probes parameters named `quantity|amount` with negative/extreme values and reports if no error response is returned.

## Steps

Save as `business_logic_scanner.py` and load via Burp Extender → Add → Python.

```python
# Burp Extension: Business Logic Scanner
# Save as business_logic_scanner.py and load in Burp Extender

from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.net import URL

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Business Logic Scanner")
        callbacks.registerScannerCheck(self)
        print("[+] Business Logic Scanner loaded")

    def doPassiveScan(self, baseRequestResponse):
        issues = []

        request = baseRequestResponse.getRequest()
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        url = request_info.getUrl()
        parameters = request_info.getParameters()

        for param in parameters:
            param_name = param.getName().lower()
            if any(keyword in param_name for keyword in ['price', 'cost', 'amount', 'total']):
                issues.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    url,
                    [baseRequestResponse],
                    "Client-Side Price Parameter Detected",
                    f"The parameter '{param.getName()}' may allow client-side price manipulation.",
                    "High"
                ))

        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        issues = []

        if insertionPoint.getInsertionPointName().lower() in ['quantity', 'amount']:
            attack_payloads = ["-1", "-100", "-999", "0", "999999"]

            for payload in attack_payloads:
                check_request = insertionPoint.buildRequest(payload)
                check_response = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(),
                    check_request
                )

                response_body = self._helpers.bytesToString(check_response.getResponse())
                if "error" not in response_body.lower() and "invalid" not in response_body.lower():
                    issues.append(CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [check_response],
                        "Negative Value Accepted",
                        f"The application accepts negative value '{payload}' in '{insertionPoint.getInsertionPointName()}'",
                        "High"
                    ))

        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "Business logic vulnerabilities allow attackers to manipulate application workflows."

    def getRemediationBackground(self):
        return "Implement server-side validation for all business-critical parameters."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Validate all user input on the server side, especially financial parameters."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
```

## Verifying success

- Burp logs `[+] Business Logic Scanner loaded` when the extension starts.
- Passive scan flags requests whose parameters contain `price|cost|amount|total`.
- Active scan reports "Negative Value Accepted" on `quantity`/`amount` parameters where the response is silent on errors.

## Common pitfalls

- Burp's Jython implementation is Python 2 only — no f-strings (`f""`). Convert to `.format()` or string concatenation.
- Active scanning can spam endpoints with destructive payloads — scope carefully.
- Many false positives — review each flagged issue manually.

## Tools

- Burp Suite Pro (Scanner / Extender)
- Jython 2.7 standalone JAR (loaded into Burp)
