# PicoCTF: Super Serial

## Context

We are provided with a website that has a login page. We are not provided any source code. The hint is: "The flag is at ../flag".

## Background Information: PHP Object Injection and Serialization

Serialization is the process of turning an object into a string. Unserialization is the reverse, turning a string back into an object. Since we are dealing with PHP, we will be converting PHP objects into strings and vise versa using `serialize()` and `unserialize()`.

If user-generated input is directly passed to an `unserialize()` function without sanitization, then malicious user-generated content could be executed, leading to file traversal, file deletion, or remote code execution, depending on the functions in the PHP script.

For example, the function `__destruct()`:

```php
function __destruct()
   {
      $file = "/var/www/cache/tmp/{$this->cache_file}";
      if (file_exists($file)) @unlink($file);
   }
```

An attacker could enter the following payload:

`http://testsite.com/vuln.php?data=O:8:"Example1":1:{s:10:"cache_file";s:15:"../../index.php";}`

This would set `cache_file` to `../../index.php`, deleting that file.

(Source at bottom of file)

## Vulnerability

The vulnerability seen in this CTF is the use of user-generated PHP object content being directly unserialized before being sanitized in any way. Also, the use of magic functions like `__toString()` are dangerous if misused.

## Exploitation

As we are given no source code for this challenge, we may try to get more information by using the `curl` command. 

We may try to visit different pages on the website. After some trial and error, we are able to find the pages `authentication.php` and `cookie.php`. These were found with the following commands:

`curl http://mercury.picoctf.net:5428/authentication.phps`

`curl http://mercury.picoctf.net:5428/cookie.phps`

The `.phps` extension is needed to see the source code of these pages. I used `curl` to get this source code since BurpSuite Repeater just gave me a "Forbidden" response. It's likely that `curl` has fewer filters, allowing us to see the source code of these pages.





## Remediation



# Sources/Credits

Written by Madalina Stoicov

- https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection
