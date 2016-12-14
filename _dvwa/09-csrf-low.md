---
title: "CSRF - Low"
permalink: /writeups/dvwa/csrf-low/
excerpt: "How to solve the CSRF challenge with the 'Low' setting."
---

---
**Note** This write-up is still in its early development phase.
{: .notice--info}


Intro TBD.
**Note** Be sure to set the DVWA Security setting to *Low* before starting the challenge.
{: .notice--info}

## About Cross Site Request Forgery (CSRF/XSRF)

According to the OWASP definition, Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. CSRF attacks specifically target state-changing requests, not theft of data, since the attacker has no way to see the response to the forged request. With a little help of social engineering (such as sending a link via email or chat), an attacker may trick the users of a web application into executing actions of the attacker's choosing. If the victim is a normal user, a successful CSRF attack can force the user to perform state changing requests like transferring funds, changing their email address, and so forth. If the victim is an administrative account, CSRF can compromise the entire web application. 

## Information Gathering & Analysis


## Conclusion


## Resources

http://www.computersecuritystudent.com/SECURITY_TOOLS/DVWA/DVWAv107/lesson10/index.html
https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)