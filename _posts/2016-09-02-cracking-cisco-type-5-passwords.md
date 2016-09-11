---
title: "Cracking Cisco 'Type 5' Passwords"
excerpt: "How to crack cisco type 5 passwords with Python."
tags:
  - python
  - cisco
  - password
---

---
I was updating my Cisco cracking tool, [cisco_pwdecrypt](https://github.com/axcheron/cisco_pwdecrypt) by adding the Cisco "Type 5" password and I thought it would be interesting to show you how to do it with Python.

## Cisco 'Type 5' Passwords

Mostly known as MD5 Crypt on FreeBSD, this algorithm is widely used on Unix systems. As Cisco uses the same FreeBSD crypto libraries on his [IOS](https://en.wikipedia.org/wiki/Cisco_IOS) operating system, the "type 5" hash format and algorithm are identical. The only exception would be that Cisco requires 4 salt characters instead of the full 8 characters used by most systems.

As a demonstration, here are the differences between Cisco's hash and original FreeBSD's hash:

```bash
# FreeBSD MD5 crypt
$ openssl passwd -1 Password123
$1$endVjKEy$x32lAjGU2Ovd7f/ZrqawV/

# Cisco "type 5" format
$ openssl passwd -1 -salt VkQd Password123
$1$VkQd$Vma3sR7B1LL.v5lgy1NYc/
```

Here is a breakdown of the hash:

```bash
$1$VkQd$Vma3sR7B1LL.v5lgy1NYc/
|-|----|---------------------|
 ^   ^    ^
 |   |    |
 |   |    `-> Hash (salt + password)
 |   |
 |   `-> base64 salt (4 chars.)
 |
 `-> Hash type (md5)
```

## Requirements

Be sure to prepare your environment first:

* Install [Python3](https://www.python.org/downloads/)
* Install the [passlib](https://bitbucket.org/ecollins/passlib/wiki/Home) module (`$ pip install passlib`)

You can use any IDE ot text editor to build your Python script. I personally use [Pycharm](https://www.jetbrains.com/pycharm/).

## Generating a Type 5 Password

The **passlib** will help us to quickly generate a "type 5" hash. Let's do a try with the following code: 

```python
$ python3

>>> # import passlib
>>> from passlib.hash import md5_crypt
>>>
>>> # generate new random salt and hash "password" 
>>> md5_crypt.encrypt("password")

# result
'$1$HyB5p1da$xPOaintEE44tgcX4.TBhZ/'
```

You can even set your own **salt** to generate the hash.

```python
$ python3

>>> from passlib.hash import md5_crypt
>>>
>>> # hash "password" with "h4cK" as salt
>>> md5_crypt.encrypt("password", salt="h4cK")

# result
'$1$h4cK$Txe7EDdFpODUBHfDwq6fG1'
```

## Cracking a Type 5 Password

To crack a hash, we'll use the **verify()** method from the **passlib** module. Let's set a dictionary to try to find the password corresponding to the following hash: **"$1$VkQd$Vma3sR7B1LL.v5lgy1NYc/"**.

```python
$ python3

>>> from passlib.hash import md5_crypt
>>> 
>>> # fake password list
>>> dict = ["password", "qwerty", "123456", "Password123"]
>>> 
>>> # hash to crack
>>> hash = "$1$VkQd$Vma3sR7B1LL.v5lgy1NYc/"
>>> 
>>> # loop and verify hash vs. password
>>> for password in dict:
...     if md5_crypt.verify(password, hash):
...             print("Password Found: %s" % password)
... 
Password Found: Password123
```

We found the password ! Easy, isn't it ?

## Conclusion

This code has been implemented in [cisco_pwdecrypt](https://github.com/axcheron/cisco_pwdecrypt). You should read the source code (as always) to have more detailed explanation and maybe enhance it !
