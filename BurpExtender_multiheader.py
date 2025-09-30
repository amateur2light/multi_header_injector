from burp import IBurpExtender, IHttpListener, ITab
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets
from javax.swing import JPanel, JLabel, JTextField, JCheckBox, JButton, JScrollPane, JTextArea
from java.util import ArrayList
import re
import time

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = callbacks.getStdout()
        self._stderr = callbacks.getStderr()

        callbacks.setExtensionName("Multi-Header-Injector")
        callbacks.registerHttpListener(self)

        # Defaults
        self.headers_text = "X-Custom-Scan-Header: my-scan-value"
        self.tools_enabled = {
            "Scanner": True,
            "Proxy": False,
            "Intruder": False,
            "Repeater": False,
            "Spider": False,
            "Target": False,
            "Extender": False,
            "Comparer": False,
            "Sequencer": False,
            "Logger": False
        }
        self.host_filters = ""   # newline separated, supports '*' wildcard
        self.path_regex = ""     # regex for path

        # Auto-update settings
        self.auto_update_enabled = False
        self.auto_update_interval = 300.0  # seconds
        self.last_update = 0.0

        # Build UI
        self._init_ui(callbacks)
        callbacks.addSuiteTab(self)

        self._callbacks.printOutput("[Multi-Header-Injector] Loaded. Edit headers and click Apply.")

    def _init_ui(self, callbacks):
        panel = JPanel(BorderLayout())

        controls = JPanel(GridBagLayout())
        c = GridBagConstraints()
        c.insets = Insets(4,4,4,4)
        c.fill = GridBagConstraints.HORIZONTAL
        c.weightx = 1.0

        # Header list label + textarea
        c.gridx = 0; c.gridy = 0; c.gridwidth = 1
        controls.add(JLabel("Custom headers (one per line, format: Header-Name: value):"), c)
        self.ta_headers = JTextArea(self.headers_text, 8, 60)
        scroll_headers = JScrollPane(self.ta_headers)
        c.gridx = 0; c.gridy = 1; c.gridwidth = 4; c.weighty = 0.0
        c.fill = GridBagConstraints.BOTH
        controls.add(scroll_headers, c)
        c.fill = GridBagConstraints.HORIZONTAL

        # Tools checkboxes
        c.gridx = 0; c.gridy = 2; c.gridwidth = 1; c.weighty = 0.0
        controls.add(JLabel("Apply to tools:"), c)
        tools_panel = JPanel(GridBagLayout())
        tc = GridBagConstraints()
        tc.insets = Insets(2,2,2,2)
        tc.fill = GridBagConstraints.HORIZONTAL
        self.chk_tools = {}
        row = 0
        tool_names = ["Scanner","Proxy","Intruder","Repeater","Spider","Target","Extender","Comparer","Sequencer","Logger"]
        for name in tool_names:
            chk = JCheckBox(name, self.tools_enabled.get(name, False))
            self.chk_tools[name] = chk
            tc.gridx = row % 2
            tc.gridy = row // 2
            tools_panel.add(chk, tc)
            row += 1
        c.gridx = 1; c.gridy = 2; c.gridwidth = 3
        controls.add(tools_panel, c)

        # Host filters textarea
        c.gridx = 0; c.gridy = 3; c.gridwidth = 1
        controls.add(JLabel("Host filters (one per line, supports * wildcard). Empty = match all:"), c)
        self.ta_hosts = JTextArea(self.host_filters, 4, 40)
        scroll_hosts = JScrollPane(self.ta_hosts)
        c.gridx = 0; c.gridy = 4; c.gridwidth = 4
        controls.add(scroll_hosts, c)

        # Path regex
        c.gridx = 0; c.gridy = 5; c.gridwidth = 1
        controls.add(JLabel("URL path regex (apply header only if path matches). Empty = match all:"), c)
        self.tf_path_regex = JTextField(self.path_regex, 60)
        c.gridx = 0; c.gridy = 6; c.gridwidth = 4
        controls.add(self.tf_path_regex, c)

        # Auto-update controls
        c.gridx = 0; c.gridy = 7; c.gridwidth = 1
        controls.add(JLabel("Auto-update from Proxy history:"), c)
        self.chk_auto_update = JCheckBox("Enable auto-update before injecting (checks proxy history)", False)
        c.gridx = 1; c.gridy = 7; c.gridwidth = 3
        controls.add(self.chk_auto_update, c)

        c.gridx = 0; c.gridy = 8; c.gridwidth = 1
        controls.add(JLabel("Auto-update interval (seconds):"), c)
        self.tf_interval = JTextField(str(int(self.auto_update_interval)), 10)
        c.gridx = 1; c.gridy = 8; c.gridwidth = 1
        controls.add(self.tf_interval, c)

        # Buttons
        self.btn_apply = JButton("Apply", actionPerformed=self._on_apply)
        self.btn_update_now = JButton("Update Now (from Proxy history)", actionPerformed=self._on_update_now)
        self.btn_test = JButton("Test Now (print settings)", actionPerformed=self._on_test)
        btn_panel = JPanel()
        btn_panel.add(self.btn_apply)
        btn_panel.add(self.btn_update_now)
        btn_panel.add(self.btn_test)

        c.gridx = 0; c.gridy = 9; c.gridwidth = 4
        controls.add(btn_panel, c)

        panel.add(controls, BorderLayout.NORTH)
        self._ui_panel = panel

    def getTabCaption(self):
        return "Multi-Header Injector"

    def getUiComponent(self):
        return self._ui_panel

    def _on_apply(self, event):
        # Save UI values
        self.headers_text = str(self.ta_headers.getText()).strip()
        for name, chk in self.chk_tools.items():
            self.tools_enabled[name] = bool(chk.isSelected())
        self.host_filters = str(self.ta_hosts.getText()).strip()
        self.path_regex = str(self.tf_path_regex.getText()).strip()

        # Auto-update settings
        self.auto_update_enabled = bool(self.chk_auto_update.isSelected())
        try:
            val = float(str(self.tf_interval.getText()).strip())
            if val <= 0:
                val = 300.0
            self.auto_update_interval = val
        except Exception:
            self.auto_update_interval = 300.0

        self._callbacks.printOutput("[Multi-Header-Injector] Settings applied. Headers lines: {}. Tools: {}. Host filter lines: {}. Path regex: '{}'. Auto-update: {} (interval {}s)".format(
            len([l for l in self.headers_text.splitlines() if l.strip()]),
            ",".join([k for k,v in self.tools_enabled.items() if v]),
            len([l for l in self.host_filters.splitlines() if l.strip()]) if self.host_filters else 0,
            self.path_regex,
            self.auto_update_enabled,
            int(self.auto_update_interval)
        ))

        # If auto-update enabled, do an immediate update (so UI values reflect latest from proxy history)
        if self.auto_update_enabled:
            try:
                self._update_headers_from_proxy_history()
            except Exception as e:
                self._callbacks.printError("[Multi-Header-Injector] Error during initial auto-update: " + str(e))

    def _on_update_now(self, event):
        try:
            self._update_headers_from_proxy_history()
        except Exception as e:
            self._callbacks.printError("[Multi-Header-Injector] Error during manual update: " + str(e))

    def _on_test(self, event):
        self._callbacks.printOutput("[Multi-Header-Injector] Current settings:")
        self._callbacks.printOutput(" Headers (raw):")
        for line in (self.headers_text.splitlines() if self.headers_text else []):
            self._callbacks.printOutput("  " + line)
        self._callbacks.printOutput(" Tools: {}".format(", ".join([k for k,v in self.tools_enabled.items() if v])))
        self._callbacks.printOutput(" Host filters (raw):")
        for line in (self.host_filters.splitlines() if self.host_filters else []):
            self._callbacks.printOutput("  " + line)
        self._callbacks.printOutput(" Path regex: {}".format(self.path_regex))
        self._callbacks.printOutput(" Auto-update: {} (interval {}s)".format(self.auto_update_enabled, int(self.auto_update_interval)))

    def _parse_headers(self):
        """
        Parse headers_text into a list of (name, value) tuples.
        Lines that do not contain ':' are ignored.
        Strips whitespace.
        """
        headers = []
        if not self.headers_text:
            return headers
        for raw in self.headers_text.splitlines():
            if not raw:
                continue
            line = raw.strip()
            if not line:
                continue
            parts = line.split(':', 1)
            if len(parts) != 2:
                continue
            name = parts[0].strip()
            value = parts[1].strip()
            if name:
                headers.append((name, value))
        return headers

    def _host_allowed(self, host):
        if not self.host_filters:
            return True
        for raw in self.host_filters.splitlines():
            pat = raw.strip()
            if not pat:
                continue
            if '*' in pat:
                regex = '^' + re.escape(pat).replace('\\*', '.*') + '$'
                if re.match(regex, host, re.IGNORECASE):
                    return True
            else:
                if pat.lower() == host.lower():
                    return True
        return False

    def _update_headers_from_proxy_history(self):
        """
        Scan proxy history (most recent first) and try to pick up value for each header name
        listed in the UI. If a header name is found in history, update the header's value in
        the UI textarea and in-memory headers_text.

        This function updates the textarea in-place and prints a short report.
        """
        target_headers = [name for (name, val) in self._parse_headers()]
        if not target_headers:
            self._callbacks.printOutput("[Multi-Header-Injector] No headers to update.")
            return

        # map lowercased header name -> latest value found
        found = {}
        history = self._callbacks.getProxyHistory()
        # iterate newest first
        for entry in reversed(history):
            try:
                req = entry.getRequest()
                svc = entry.getHttpService()
                reqInfo = self._helpers.analyzeRequest(svc, req)
                hdrs = reqInfo.getHeaders()
                for h in hdrs:
                    idx = h.find(':')
                    if idx <= 0:
                        continue
                    hname = h[:idx].strip()
                    hval = h[idx+1:].strip()
                    lname = hname.lower()
                    if lname in found:
                        continue
                    # if this header is one we care about, record it
                    for t in target_headers:
                        if t.lower() == lname:
                            found[lname] = hval
                            break
                # optimization: stop if we've found all
                if len(found) >= len(target_headers):
                    break
            except Exception:
                # ignore malformed/history entries
                continue

        if not found:
            self._callbacks.printOutput("[Multi-Header-Injector] No matching headers found in Proxy history.")
            return

        # Rebuild headers_text replacing values for headers we found
        new_lines = []
        changed = []
        for raw in self.headers_text.splitlines():
            line = raw.strip()
            if not line:
                new_lines.append(raw)
                continue
            parts = line.split(':', 1)
            if len(parts) != 2:
                new_lines.append(raw)
                continue
            name = parts[0].strip()
            lname = name.lower()
            if lname in found:
                new_val = found[lname]
                new_lines.append(name + ": " + new_val)
                changed.append((name, new_val))
            else:
                new_lines.append(raw)

        if changed:
            self.headers_text = "\n".join(new_lines)
            # Update UI textarea on Swing thread
            try:
                self.ta_headers.setText(self.headers_text)
            except Exception:
                # best effort
                pass

            self.last_update = time.time()
            self._callbacks.printOutput("[Multi-Header-Injector] Updated headers from Proxy history:")
            for (n,v) in changed:
                self._callbacks.printOutput("  {}: {}".format(n, v))
        else:
            self._callbacks.printOutput("[Multi-Header-Injector] No headers replaced (none found in Proxy history).")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process requests
        if not messageIsRequest:
            return

        # Map tool flag to name
        tool_map = {
            self._callbacks.TOOL_SCANNER: "Scanner",
            self._callbacks.TOOL_PROXY: "Proxy",
            self._callbacks.TOOL_INTRUDER: "Intruder",
            self._callbacks.TOOL_REPEATER: "Repeater",
            self._callbacks.TOOL_SPIDER: "Spider",
            self._callbacks.TOOL_TARGET: "Target",
            self._callbacks.TOOL_EXTENDER: "Extender",
            self._callbacks.TOOL_COMPARER: "Comparer",
            self._callbacks.TOOL_SEQUENCER: "Sequencer",
        }

        tool_name = tool_map.get(toolFlag, None)
        if tool_name is None:
            return

        # Check if this tool is enabled
        if not self.tools_enabled.get(tool_name, False):
            return

        try:
            # If auto-update enabled and interval elapsed, refresh header values from Proxy history
            if self.auto_update_enabled:
                now = time.time()
                try:
                    interval = float(self.auto_update_interval)
                except Exception:
                    interval = 300.0
                if now - self.last_update >= interval:
                    try:
                        self._update_headers_from_proxy_history()
                    except Exception as e:
                        self._callbacks.printError("[Multi-Header-Injector] Auto-update error: " + str(e))

            request = messageInfo.getRequest()
            httpService = messageInfo.getHttpService()
            reqInfo = self._helpers.analyzeRequest(httpService, request)
            headers = reqInfo.getHeaders()
            url = reqInfo.getUrl()
            host = httpService.getHost()

            # Host filter
            if not self._host_allowed(host):
                return

            # Path filter
            if self.path_regex:
                path = url.getPath() or "/"
                try:
                    if not re.search(self.path_regex, path):
                        return
                except Exception as e:
                    self._callbacks.printError("[Multi-Header-Injector] Invalid path regex '{}': {}".format(self.path_regex, str(e)))
                    return

            # parse headers from UI
            headers_to_add = self._parse_headers()
            if not headers_to_add:
                return

            # Build case-insensitive set of existing header names
            existing = set()
            for h in headers:
                idx = h.find(':')
                if idx > 0:
                    name = h[:idx].strip().lower()
                    existing.add(name)

            # Add headers that are not present
            newHeaders = ArrayList()
            for h in headers:
                newHeaders.add(h)

            added_any = False
            for (name, value) in headers_to_add:
                lname = name.lower()
                if lname in existing:
                    continue
                newHeaders.add(name + ": " + value)
                added_any = True

            if not added_any:
                return

            # Extract body
            body_offset = reqInfo.getBodyOffset()
            body = request[body_offset:len(request)]

            # Build new request and set
            newRequest = self._helpers.buildHttpMessage(newHeaders, body)
            messageInfo.setRequest(newRequest)

            self._callbacks.printOutput("[Multi-Header-Injector] Injected headers for host {} url {}".format(host, url.toString()))
        except Exception as e:
            self._callbacks.printError("[Multi-Header-Injector] Error in processHttpMessage: " + str(e))
