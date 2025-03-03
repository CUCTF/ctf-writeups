Lab: Web shell upload via extension blacklist bypass
We will start the same as before, logging in and trying to upload our malicious php file
We get an error “Sorry, php files are not allowed Sorry, there was an error uploading your file.”
Note: this is not an issue where we can just change the Content Type. It is specifically analyzing the extension of our file
Therefore we know that the php extension is blacklisted. Let’s see if we can get around this
We can try uploading our own configuration file to be able to allow php
First we need to see what kind of server we are running on. 
When we tried to upload our file, we got a Server: Apache/2.4.41 (Ubuntu) tag in the response, so we know that we are on an Apache server
I made an apache2.conf file that has the lines:
 	LoadModule php_module /usr/lib/apache2/modules/libphp.so
		AddType application/x-httpd-php .php
Let’s try uploading this
Indeed, we get back a message: The file avatars/apache2.conf has been uploaded
Now we can try uploading our php file again
It does not work.
Therefore, that specific file kind that gives us php access was not the right one
We need to modify the file we upload
We only need to have the AddType
We also need to call it .htaccess to match the files that are already on the server
We can’t upload that file from our desktop (it won’t find .htaccess), so we will have to manually edit the HTTP request as such:

Let’s try uploading our php file again
We still get an error
We need to route through another file type
Change rce.php into some other file type (like .shell or, as is suggested by PortSwigger, .133t which is just some arbitrary type; or .lmao)
Put the AddType line directly into the request
Still keep it named .htaccess
------WebKitFormBoundary4WUiAJYmzPhpu9jd
Content-Disposition: form-data; name="avatar"; filename=".htaccess"
Content-Type: text/plain


AddType application/x-httpd-php .lmao


Now finally when we upload our web shell code (which we named to rce.lmao), we get success:  The file avatars/rce.lmao has been uploaded.
Navigate to carlos to get the secret
Go to …web-security-academy.net/files/avatars/rce.lmao
And we have our solution

