# Burp Multi-Header Injector

> Add and auto-refresh authentication or custom headers for Burp Scanner and other tools.  
> Designed for authenticated/automation scans where Burp's built-in auto-login, Sequencer or session automation fails (for example:- When 2FA or short-lived tokens are used).

---

## Overview

**Burp Multi-Header Injector** is a Jython extension for Burp Suite that lets you inject multiple custom headers into outgoing requests for selected Burp tools. It can automatically refresh header **values** from Burp's Proxy history, which is useful when tokens or cookies rotate frequently or when interactive logins (with 2FA) are required to obtain new credentials.

Key capabilities:
- Inject multiple headers (one per line, `Name: value`) into requests from selected Burp tools (Scanner, Intruder, Repeater, etc).
- Avoid duplicate headers (case-insensitive).
- Restrict injection by host filters (supports `*` wildcard) and URL path regex.
- Auto-update header values from Proxy history (newest-first), with manual "Update Now" and configurable interval.
- Lightweight UI inside Burp (no recompilation; requires Jython).

---

## Features

- **Multi-header editor** - add multiple `Header-Name: value` lines.
- **Tool selection** - choose which Burp tools receive the injected headers.
- **Host & path filtering** - apply headers only to specific hosts or paths.
- **Auto-update** - refresh header values automatically from Proxy history to keep tokens current.
- **Manual refresh** - one-click "Update Now (from Proxy history)".
- **Safe behavior** - the extension skips adding headers that already exist in the outgoing request (case-insensitive).

---

## Use Cases

- Performing authenticated scans when automated login fails due to 2FA.
- Keeping rotating API tokens, session cookies or custom headers fresh during long scans.
- Injecting gateway-specific headers required for access to internal APIs.

---

## Requirements

- **Burp Suite** (Community or Professional) with Extender support.
- **Jython standalone JAR** configured in Burp:
  - Burp → Extender → Options → Python Environment → select `jython-standalone-<version>.jar`.
- The extension file: `BurpExtender_multiheader.py`.
- Proxy history should contain successful login requests if you want AutoUpdate to extract header values.

---

## Installation

1. Save the extension as `BurpExtender_multiheader.py`.
2. Download the Jython standalone JAR (e.g. `jython-standalone-2.7.2.jar`) if you don't have it.
3. Configure Jython in Burp:
   - Burp → Extender → Options → Python Environment → Select the Jython standalone JAR.
4. Load the extension:
   - Burp → Extender → Extensions → Add → Type: **Python** → Select the `.py` file.
5. Open the **Multi‑Header Injector** tab (suite tab) in Burp.

---

## Quick Start

1. In the extension UI, add headers one per line:
   ```
   Authorization: Bearer PLACEHOLDER
   X-Auth-Token: placeholder-token
   Cookie: sessionid=placeholder
   ```
2. Select the Burp tools you want to affect (e.g., **Scanner**, **Proxy**).
3. (Optional) Add host filters (one per line):
   ```
   api.example.com
   *.staging.example.local
   ```
4. (Optional) Add a URL path regex, for example:
   ```
   ^/api/v[0-9]+/
   ```
5. Enable **Auto‑update** and set the interval (seconds), or click **Update Now** to refresh immediately.
6. Click **Apply**.
7. Run your scan or issue requests from the selected tools - headers will be injected where appropriate.

---

## How AutoUpdate Works

- The extension scans Burp’s Proxy history (most recent first) using `callbacks.getProxyHistory()`.
- For each header name listed in the editor, it searches for the most recent request that contains that header name and captures its value.
- Found values replace the existing values in the editor and in-memory configuration.
- AutoUpdate runs automatically before injection if the configured interval has elapsed; it also runs immediately when you click **Apply** with AutoUpdate enabled.
- **Important:** AutoUpdate only **replaces header values** for header names already present in your header editor - it does not add new header names automatically.
- **Note:** The extension works well while you are performing manual testing or have extended session expiry. If your application has session expiry due to user inactivity use [Session-Pilot](https://github.com/amateur2light/Session-Pilot) in parallel.

---

## Configuration Options

- **Custom headers:** `Name: value` format, one per line.
- **Apply to tools:** Checkboxes for Scanner, Proxy, Intruder, Repeater, Spider, Target, etc.
- **Host filters:** One per line. Supports `*` wildcard (e.g., `*.example.com`). Empty = match all hosts.
- **Path regex:** Only inject when the URL path matches this regex. Empty = match all paths.
- **Auto-update:** Enable to refresh values from Proxy history. Set interval in seconds or click **Update Now**.

---
