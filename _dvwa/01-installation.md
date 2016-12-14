---
title: "Installation"
permalink: /writeups/dvwa/installation/
excerpt: "How to install DVWA on Debian."
---

---
Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable. Its main goal is to be an aid for security professionals to test their skills and tools in a legal environment, help web developers better understand the processes of securing web applications and to aid both students & teachers to learn about web application security in a controlled class room environment.

This procedure is based on the [official documentation](https://github.com/ethicalhack3r/DVWA) of the DVWA. I suggest you to read it if you need more details.

## Disclaimer

The **DVWA** is vulnerable by design ! Do not upload it to your hosting provider's public html folder or any Internet facing servers, as they will be compromised. It is recommend using a virtual machine (such as *VirtualBox* or *VMware*), which is set to NAT networking mode.

**I do not take responsibility** for the way in which any one uses this application (DVWA). I have made the purposes of the application clear and it should not be used maliciously. I have given warnings and taken measures to prevent users from installing DVWA on to live web servers. If your web server is compromised via an installation of DVWA it is not mt responsibility it is the responsibility of the person/s who uploaded and installed it.

## Installation

We start this installation from a Debian based Linux distribution. I suggest you to use the [Debian Netintall](https://www.debian.org/CD/netinst/) to have a minimal Linux environment.

One your Debian is fully setup, run the following command to install the dependencies. Be sure to remember the password you set while installing MySQL.

```bash
sudo apt-get -y install apache2 mysql-server php5 php5-mysql php5-gd git
```

**Note** As you can see, I'm using the `sudo` command. If you don't want to run as **root**, install `sudo` by running `apt-get install sudo` (as root), then type `sudo adduser <username> sudo` to add your user as a sudoer.
{: .notice--info}

Now, clone the DVWA repository in the `/var/www/` folder.

```bash
cd /var/www
sudo rm -rf html
sudo git clone https://github.com/ethicalhack3r/DVWA.git .
```

**Note** Be sure to add the *dot* (**.**) at the end of the `git` command.
{: .notice--info}

Then, edit the `config.inc.php` in `/var/www/config/` to configure the database password.

```bash
# Database variables
#   WARNING: The database specified under db_database WILL BE ENTIRELY DELETED during setup.
#   Please use a database dedicated to DVWA.
$_DVWA = array();
$_DVWA[ 'db_server' ]   = '127.0.0.1';
$_DVWA[ 'db_database' ] = 'dvwa';
$_DVWA[ 'db_user' ]     = 'root';
$_DVWA[ 'db_password' ] = 'p@ssw0rd';
```

To be sure that all the challenges are running properly, we have to edit some PHP settings in `/etc/php5/apache2/php.ini`.

```bash
allow_url_include = On  # Allows for Remote File Inclusions
allow_url_fopen = On # Allows for Remote File Inclusions
safe_mode = Off # (If PHP <= v5.4) Allows for SQL Injection
magic_quotes_gpc = Off # (If PHP <= v5.4) Allows for SQL Injection
display_errors = Off # (Optional) Hides PHP warning messages to make it less verbose
```

We also have to edit the Apache configuration in `/etc/apache2/sites-enabled/000-default.conf`, to change the `DocumentRoot` with the parameter `/var/www/`. Then set the proper rights on the `/var/www/` folder by running `sudo chown -R www-data:www-data /var/www`

Restart the Apache service, `sudo service apache2 restart` and go to http://your_ip/setup.php.

## DVWA setup

Once you access the setup page, all the parameters should be **green** except the reCAPTCHA key.

![image-center](/images/dvwa/dvwa-setup-check.png){: .align-center}{:width="600px"}

**Note** The `reCAPTCHA key` parameter is used for the *Insecure CAPTCHA* challenge. It will be needed if you only want to solve the *Insecure CAPTCHA* challenge, but I didn't wrote any write-up for it yet. You will have to wait !
{: .notice--info}

Click on the *Check / Reset Database* button at the bottom of the page. If everything worked fine, you should get the following result:

![image-center](/images/dvwa/dvwa-db-setup.jpg){: .align-center}{:width="350px"}

Then, you on the DVWA by using the following link: http://your_ip/login.php. The default usernmame is: **admin** and the password is: **password**.

## Install DVWA with Vagrant

**Coming Soon**

## Resources

* [DVWA Github](https://github.com/ethicalhack3r/DVWA)
* [DVWA Homepage](http://www.dvwa.co.uk)