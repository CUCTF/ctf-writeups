# PortSwigger Lab: Web shell upload via extension denylist bypass

## Context

We are provided a website with a home page and "My Account" page where someone can login to their account. The account login information (username and password) is given in the lab prompt. Upon logging into the account, we may upload a photo to act as an "avatar" (profile photo) for our account. 

This section of PortSwigger Academy is about file upload vulnerabilities, so we know that that is what we must work towards. However, if this were in a CTF setup, file upload vulnerabilities would be the next thing we would check for to get our flag.

As a note, the term "denylist" will be used here instead of "blacklist".

## Background Information: File Upload Vulnerabilities

File upload vulnerability is when a web server allows a file to be uploaded without checking its name, type, size, or other attributes. If a file isn't checked before it is uploaded, an attacker would be able to upload malicious code. In the worst case, an attacker would be able to upload a shell and gain remote code execution.

Cases of file upload vulnerabilities:
- A file's type isn't validated (this includes Content-Type restrictions, denylisting an extension, etc. This would occur because the website is not configured to process that filetype)
- A file's name isn't validated
- A file's size isn't validated
- A file's contents aren't validated (this includes exploits of embedding metadata into an image and uploading that)

More about denylisting:
- Someone may try to protect their website from file upload vulnerabilities by not allowing certain common malicious extensions to be uploaded, such as .php.
- Denylisting can fail in many ways:
  	- Fail to denylist obscure malicious file types
  	- Fail to account for parsing discrepancies when parsing the extensions
  	- Fail to allow uploads to configure a certain file-type to be uploaded

Let's say we find a type of file that is denylisted and we can't upload it (we recieve a message or some other signal that that type of file is not allowed). We have two options to continue to try to upload the file:
1. Use obfuscation to play around with the file extension (example: exploit.asp%00.jpg)
2. Try to upload a code block to configure a certain filetype, and disguise that configuration file as a normal configuration file (such as .htaccess, which would allow you to make directory-specific configurations on Apache servers).

In order to exploit a denylisting vulnerability, we may find it useful to use PortSwigger's BurpSuite to analyze HTTP requests and responses between the website and the server. 

## Vulnerability

After logging in (with our given credentials), we can try to upload a file. 

We will try to upload a basic, malicious PHP file that, when successful, will result in remote code execution:

exploit.php:

`<?php echo file_get_contents('/home/carlos/secret'); ?>`

The filepath `/home/carlos/secret` is given to us by the lab prompt. In a CTF setting, the filepath may be set to some other directory where the flag could be found. Or, since this will result in remote code execution when successful, it could be a home directory where you navigate from there.

When we try to upload this file, we get a message: “Sorry, php files are not allowed Sorry, there was an error uploading your file.” We see that PHP files are not allowed to be uploaded. Additionally, we should note that the error is saying that the site is running on an Apache server.

Various exploits could be attempted from here, such as:
- Editing Content-Type restrictions: In the POST request to the server, change Content-Type from `text/php` to a possibily valid type like `image/jpg`.
- Using obfuscation to edit the .php extension

For this lab, neither of those methods worked. We may try a denylisting exploit. Indeed, we are able to upload a configuration file to alter what file types are allowed to be uploaded.

The vulnerability here is that a .htaccess file (or a file that is renamed to .htaccess once entered into BurpSuite) can be uploaded to add a new file type to be uploaded.

## Exploitation

Let's try to upload a code block that would allow a certain file type to be uploaded.

From the PortSwigger file upload notes we are given the following code block for an Apache configuration file:

`LoadModule php_module /usr/lib/apache2/modules/libphp.so
      AddType application/x-httpd-php .php`

Let's take just the `AddType` line and add it into a PHP file (that is all we need for configuration). We know that for this to be a valid configuration file it needs to be called `.htaccess` for Apache servers. I tried to name my file `.htaccess` directly, but because it started with a . I was unable to select it when choosing a file to upload. So, I named it `rce.php`.

There is one more change that needs to made. Instead of trying to make it so that the server will allow .php specifically, we need to re-route through another file type. This can be a self-made type, I chose `.lmao` (why not!).

`rce.php` will look as follows:

`AddType application/x-httpd-php .lmao`

We will upload `rce.php`, but before sending it off, we must make edits to the POST request in BurpSuite. We need to change the name of the file to `.htaccess` to match Apache configuration files. We can make this change in the `filename=` portion of the request. We should also change Content-Type to `text/plain` so the file is not detected as PHP from that field.

Send off the modified POST request, and we get a successful message: "The file avatars/config.lmao has been uploaded."

Now that `.lmao` files can be uploaded, we may go back and upload exploit.php, but modify the name in the POST request to `exploit.lmao`. 

Now we simply navigate to where the file was uploaded to recieve our flag: .../files/avatars/exploit.lmao.

## Remediation

One way to prevent this kind of vulnerability is to block files named `.htaccess`. Or, in general, just rename files before letting them be uploaded. Additionally, don't let files be added to the permanent file system before being fully validated.

# Sources/Credits

Written by Madalina Stoicov

- https://portswigger.net/web-security/learning-paths/file-upload-vulnerabilities
