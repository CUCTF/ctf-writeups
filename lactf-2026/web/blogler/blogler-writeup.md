# LA CTF 2026: web/blogler

## Context
Blogler is a blogging platform built in Flask where users register an account and write blog posts in Markdown. Users are also able to modify YAML configuration. 

The code has built-in checks for `../` and `/`(root) directory traversal in the YAML configuration. 

The **goal of the challenge** is to find the flag in a flag file on the server. 

### Background information on YAML
YAML ("Yet Another Markup Language" or "YAML Ain't Markup Language") is a data serialization language used for file configuration and data exchange between different systems. It is similar to JSON or XML but does not need to use brackets and braces, rather relying on indentations like Python. 

## Vulnerability
The website is built with Flask, which defines routes that map URLs to specific view functions.

In app.py, each GET request is defined using decorators. For example, `@app.get("/blog/<string:username>")` defines a dynamic route that retrieves the blog posts for a specific username.

By manipulating the username of the user, you are able to traverse different routes. 

For example, changing the username to `../login` causes clicking the blog to redirect to the login page, and `../config` causes clicking the blog to redirect to the config page.

Since this allows us to traverse, we can use this to find `/flag` in the server.

## Exploitation
Although such traversal can result in different routes, there is no `/flag` decorator defined so we cannot directly reach the flag.

There are a couple of other things to notice in order to make this work. First, the display_name function used to remove underscores and make usernames more readable or user friendly. Second, YAML supports anchors (&) and aliases (*), which creates references to the same object specified.


Using these points, we can craft a method to dump the flag file to the screen. 

Originally, I thought there needed to be a specific username and password defined, but that is not necessary because the username and password will be changed later anyways.

Next, in the config editor, we want to alias and anchor `user` and a blog under `blogs` together like 
```
blogs:
  - &ref
    name: "hi_blog_4b7f6c44a31806e7.md"
    title: "hi"
user: *ref
```

Now, since `user` and the blog under `blogs` reference the same object, the name for that blog will become the new user name because both user and blog have a `name` field which allows this to work. We can change the `name` to be a directory traversal that takes advantage of the display_name function's underscore removal. For example: `._._/._._/flag` or `_.._/_.._/flag`.

```
blogs:
  - &ref
    name: "._._/._._/flag"
    title: "flag"
user: *ref
```

Update the config, which changes the config to display: 
```
blogs:
- &id001
  name: ../../flag
  password: hi
  title: Blog Title
user: *id001
``` 
The flag path is now ready. Now, clicking blogs will bring you to the blogs page of the user with your original username, but that one specific blog will print the flag because of `"content": mistune.html((blog_path / blog["name"]).read_text())` where `blog_path/../../flag` brings you to the flag file and `.read_text()` would allow the flag to be printed.



## Remediation
This exploitation takes advantage of different features in the functionality of the program including the display_name function for the username, YAML's alias and anchors feature, and the way blogs are retrieved for users.

To prevent such exploitations, the programmer can add more validations against local file inclusion attacks, particularly checking for path traversals (`../` and `/`), and using `is_relative_to()` after all modifications and before passing to a functionality. 

Although we didn't particularly take advantage of the username and password customization in this exploitation, the programmer should also add input validation for the blog and registration (which they wrote `TODO` comments on). This will also prevent the directory traversals using custom usernames through the `/blogs` page. 


## Other

### Other things I noticed
1. In `app.run()`, debug is set to True. My initial thought process was to have that dump users if there may possibly be an admin user.

2. `/login` doesn't actually work. It gets redirected to a `/home` page that doesn't exist.

