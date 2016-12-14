---
title: "Brute Force - Low"
permalink: /writeups/dvwa/bruteforce-low/
excerpt: "How to solve the Brute Force challenge with the 'Low' setting."
---

---
In this write-up, we will try to find valid credentials for the **Brute Force** challenge. We will use the *Low* security setting of **DVWA** to understand how this attack work and then, we will be able to move on to harder security settings. For the sake of the challenge, we will assume that we don't know the credentials because, as you guessed it, `admin:password` will work against the login form.

To solve this challenge, we will analyze the login form and then move on to the solution using a custom Python script and a tool called [Patator](https://github.com/lanjelot/patator). I will also provide some interesting links on other solutions at the end of this write-up.

**Note** Be sure to set the DVWA Security setting to *Low* before starting the challenge.
{: .notice--info}

## About Brute Force

According to the OWASP definition, a brute force attack consists in an attacker configuring predetermined values, making requests to a server using those values, and then analyzing the response. For the sake of efficiency, an attacker may use a dictionary attack (with or without mutations) or a traditional brute-force attack (with given classes of characters e.g.: alphanumerical, special, case (in)sensitive).

Indeed, the password guessing  method is very fast when used to check all short passwords, but for longer passwords other methods such as dictionary attack are used because a pure brute-force search takes too long.

## Information Gathering & Analysis

Once logged in to DVWA, go to the **Brute Force** tab and try a random username/password. We can see two things: 

* The web application gives us an error message `Username and/or password incorrect.`
* The credentials are sent using the **HTTP GET** method `http://192.168.212.160/vulnerabilities/brute/?username=test&password=test&Login=Login#`

By taking a look at the HTML source, we can confirm that the credentials are sent using the HTTP GET method.

```html
	<h1>Vulnerability: Brute Force</h1>

	<div class="vulnerable_code_area">
		<h2>Login</h2>

		<form action="#" method="GET">
			Username:<br />
			<input type="text" name="username"><br />
			Password:<br />
			<input type="password" AUTOCOMPLETE="off" name="password"><br />
			<br />
			<input type="submit" value="Login" name="Login">
		</form>
	</div>
```

## Getting the Session Cookie with Burp

As we are logged in to DVWA, we need to get our sesssion cookie to get our tools to work while bruteforcing the login form.



## PoC in Python

So now, we know how the application send our credentials to the web server and how the web server responds when the credentials are invalid. We will now automate the try and error process by using a simple Python script.

To deal with HTTP in Python, we will use the *requests* module.

## Solving the Challenge with Patator


## Conclusion


## Resources

* [DVWA Brute Force Solution with Burp](https://pentestlab.blog/2012/12/21/brute-force-attack-with-burp/)
* [DVWA Brute Force Solution by g0tmi1k](https://blog.g0tmi1k.com/dvwa/bruteforce-low/)
* [Brute Force Definition from OWASP](https://www.owasp.org/index.php/Brute_force_attack)
* [Patator.py Source Code on GitHub](https://github.com/lanjelot/patator)
