# Backend Vulnerabilities

## SQLi
### What is it?
SQL Injection is a common web vulnerability found in dynamic sites that is caused by unsanitized
user input, which is then passed on to a database.  This user input can then be manipulated to
“break out” of the original query made by the developers, to include more malicious action
The authentication bypass is a classic SQL injection example that effectively demonstrates the
dangers of evil users playing with your database. Let’s examine the admin page again and take a
look at its underlying source code:

```php
mysql_select_db('webappdb')
$user = $_POST['user']
$pass = $_POST['pass']

$query="SELECT * FROM users WHERE name = '$user' AND password = '$pass'"

$queryN = mysql_query($query) or die(mysql_error())
if (mysql_num_rows($queryN) == 1) {
$resultN = mysql_fetch_assoc($queryN)
$_SESSION['user'] = $_POST['user']
}
```

Given that a log-in query might look something like this:

```sql
$query="SELECT * FROM users WHERE name = 'john' AND password = 'hunter2'"
```

Passing a malicious string, `admin' or 1=1;#` would take over the query.

```sql
 select * from users where name='admin' or 1=1;# and password='wrongpass';
```

Let's take this a step past just authentication bypass and actually extract sensitive information
from a database.

Depending on the verbosity of the web application, an attacker could try to use the “order by”
output query to gather information about the database structure. The "order by" query instructs the
database to order the output results, using the first column in the select query as reference. If
you continue to increase the column count until you see anomalous behavior, you will have just
enumerate how many columns this table has.

For this next step, consider an application that lists items for sale in a list format. Your
`items` table has 7 columns. Your item list shows a price, an item name, and a phone number. When
you inject the query by visiting `/items?id=1 union all select 1,2,3,4,5,6,7` you notice an item on
the list where instead of seeing the name, price, and phone number, you see a row with the numbers
1, 5, and 6. This means that those numbers match with the column names, respectively. You can begin
to replace the numbers in your query with other function or sub-queries. Replacing the number 6
with `@@version` will print the database version number in the 'phone_number' column. Same with
`user()`, which tells you the user under which the database process is running. Let's pull a little
more information from the table.

Chances are the query we've hijacked is just querying the `items` table in this database. Let's
change that.

First we have to see what tables there are. We can print the tables for the existing database by
querying the `information_schema` table.

```
/items?id=1 UNION ALL SELECT table_name,2,3,4,5,6,7 FROM information_schema.tables
```

This returns a list of all tables on the webapp's database. To pull columns from the `users` table,
we can inject:

```
/items?id=1 UNION ALL SELECT column_name,2,3,4,5,6,7 FROM information_schema.columns WHERE
table_name='users'
```

The email and password are the fields we're interested in here. So let's pull those out.

```
/items?id=1 UNION ALL SELECT concat(email,0x3a,password),2,3,4,5,6,7 FROM users
```


This walks through a single type of injection. We got lucky in that we had feedback by way of the
items table. Certain types of injection are harder to exploit, like time-based, boolean, and blind
SQL injection.


### Solution

If you have to create your own queries, make sure you use bind parameters for all user-supplied
input.

If choosing an ORM, review the library's past issues and have a security review conducted.

### Examples

Avoid creating queries by concatenating strings with variables. Even data from HTTP headers,
cookies or even IP addresses can be used by an attacker to exploit SQLi. If you must do it (for
example for sort field), use a white-list of known valid values only. The link below shows a blind
SQLi on the Oculus developer portal caused by unsafely including data from the X-Forwarded-For
header in a query.

[Hacking Oculus with Header Value](https://bitquark.co.uk/blog/2014/08/31/popping_a_shell_on_the_oculus_developer_portal)


## IDOR
### What is it?
Indirect object reference occurs when a user references an identifier to load content, but the
identifier is not properly validated against the user's level of access. A simple example can be
thought of as a reciept for a purchase displayed to a user, with a numerical identifier in the URL
identifying the transaction number. An attacker sees this number, and realizes they can modify it
to view other user's reciepts.

Another example can involve updating user profile information. An authenticated user makes an
update profile request to the server, and in the body of the request, a sequential numeric
identifier is used to tell the server which user profile to update. An attacker realizes they can
modify this identifier and the server then allows the attacker to update the profile information of
other users.


### Solution
When a request comes in, and a user requests access to data, or attempts to modify data, the
backend server must always validate that the user has permission to modify the data in question.
Simply verifying that the user is logged in is not sufficent in many cases, because of different
levels of permissions within the application. For example, perhaps you should have access to your
own reciept, but referencing the identifier for another user's recpiet should have an additional
check on it to verify if it belongs to the user or not, before serving it.

### Examples
In late 2010 and early 2011, a man named Aaron Swartz downloaded millions of academic journels
intended to have authorization controls, simply by changing one parameter in the URL containing a
numeric identifier. He was later brought up on charges for violating the computer fraud and abuse
act and faced a up to 35 years in jail.


## SSRF / RFI / File Upload
### What is it?
Including libraries or other scripts in your code is something we do every day. Sometimes we try to
dynamically include code/files based on user input. This is usually not a good idea as it opens up
the possibility for the user to inject his own code if input validation is not done properly.

These vulnerabilities have to do with read/writing files to/from the server that are not meant to be
read/written to. Reading config files can aid an attacker in shaping their attack, expose secrets,
enumerate internal networks, etc. Writing to a server whose application runs interpreted code means
an attacker could add backdoor, replace app logic to siphon logon attempts by patching login
functions, even attain a shell on the applications underlying infrastructure.


### LFI/RFI
Forcing a request to the application to read a file, either local or remote. Sometimes these
resources are code. In the case of an RFI vulnerability, that could mean adding completely
custom, attacker-written code into your application. An LFI vulnerability could allow an attacker to
read proprietary application code or underlying configuration files. If an attacker can pollute web
logs, they can essentially write code to disk and have the web application execute it by requesting
the log file with a request like `/?page=../../../../var/log/nginx/access.log`


### SSRF
Server-Side Request Forgery can be defined as tasking a server to read from another resource. It's
only slightly different from LFI/RFI. It might be easier to think of SSRF as Second-Order LFI/RFI.

### Uploads
Unrestricted file upload is often easily exploitable by uploading some server side code. Even if
the server will not execute server side code, it could be possible to upload HTML files in order to
exploit XSS (remember that even svg files can cause XSS if loaded directly in the browser). Even
just uploading a .htaccess file can often cause lots of trouble.

### Solution
Ensure that any app logic based on files or URIs is not able to be influenced by user input, either
directly or by nth order.(logs, artifacts, etc.) It's also important to understand the different
URI wrappers that can be abused.

```
* file://
* ssh://
* ftp://
* http://
```

Never perform any requests to URLs supplied by user without doing validation first

Besides checking for file extension, mime type and magic numbers, you should check if attacker is
trying to perform a path traversal attack in order to save a file in an unintended location, like
../../../etc/nginx/nginx.conf. Allow users to upload files only on blob storage/separate domain
because all mentioned input validation can often be bypassed, as show in the link below.


### Examples
If your app is making requests to URLs that are provided by the user, use a whitelist of allowed
URLs if possible (if not, host app on sandboxed host). Otherwise the user could specify internal
addresses which can lead to unexpected results. SSRF is often just the first step to a more serious
exploit. Sometimes SSRF is achieved not by directly processing a URL, but indirectly, by processing
files that are referencing some other files or URLs (if you are processing videos, an attacker can
make the ffmpeg library embed /etc/passwd in the video as the subtitle… although this would be
classified as LFI rather than SSRF, it’s a similar principle). The link below shows how a harmless
SSRF can be chained with other bugs to achieve RCE.

[Getting Shell on Github](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html)


## Remote Command Execution / Command Injection
### What is it?

Most of the above vulnerabilities can be chained to ultimately achieve code execution. Direct RCE
is rare, but still happens occasionally. It's often introduced by 3rd party libraries or failing to
validate input before passing user-supplied input to `eval` or `exec`-like commands.

### Solution

User-supplied input should never be passed to any kind of `eval` or `system()`-like functions.
These functions should be used sparingly but if they are necessary, ensure that input is verified
against a whitelist.

### Examples

Using the latest version of some library does not guarantee that the there are no security
implications. Library authors often leave some implementation details to the users of the
libraries, which if not done correctly can lead to serious vulnerabilities. Facebook ended up
paying $40K for an unsafely implemented imagemagick library.

[Sites Allowing Image Uplodes At Risk](http://4lemon.ru/2017-01-17_facebook_imagetragick_remote_code_execution.html)


Command injection is possible if application is running OS commands with user supplied data. The
user could simply use semicolon (or some other characters like ||, &&, %0a…) to escape the current
command and run a new one if input validation is not done correctly

[Ruby Standard Library Command Execution](https://hackerone.com/reports/294462)


## Deployment of Sensitive Development Files
### What is it?
When deploying applications, engineers should take care not to include meta, config or test files.
These can and do include sensitive details such as tokens, passwords and test endpoints used.
### .git - Allowing for Access to Source Code
When deploying a web application, administrators can sometimes just clone the repository. 
Most version control systems create a meta folder in the root directory of the project. 
This can allow a nefarious user to explore previous commits and extract source code:
```
wget -r http://demo.target.com/.git/
cd demo.target.com
git checkout *.php; ls;
```
### Example
[Exposure of Git repo and other files](https://hackerone.com/reports/248693)

### package.json - Access to Dependencies, Endpoints etc
Similar to deploying .git - Deploying package.json and associated config files can allow for leakage of sensitive details like API keys, package versions.
```
{
  "name": "node-js-sample",
  "version": "0.2.0",
  "description": "A sample Node.js app using Express 4",
  "main": "index.js",
  "scripts": {
    "start": "node index.js"
  },
  "dependencies": {
    "express": "^4.13.3"
    ...
```
### Example
[Accidental deployment of API Keys via package.json](https://github.com/observing/fullcontact/issues/31)
### Build variables exposed via CI/CD tooling
Authentication/Authorisation data should not be hardcoded in config files - such as those used to initiate builds in the pipeline.
For instance Travis CI is a hosted, distributed continuous integration service used to build and test software projects hosted at GitHub.
It stores build variables in a yaml or js files. For instance travis.yml.
```
Setting environment variables from .travis.yml
$ export CXX=g++-4.8
$ export SAUCE_USERNAME=instantuserjs
$ export SAUCE_ACCESS_KEY=zxzxzxzx-c8d3-ccxx-8710-4d66992514ac
$ export GH_TOKEN=[secure]
$ export CACHE_URL=[secure]
```

### wp-config.php - Leaking DB Users, Passwords, Tokens
Spinning up a wordpress instance can include config files by default that contain passwords, tokens etc.
The default wp-config contains items such as:
```
 define('ENVIRONMENT', 'prod');
    define('WP_DEBUG', false);
    define('MOBILEURL', 'subdomain.test.com');
    define('DB_NAME', 'pii');
    define('DB_USER', 'user');
    define('DB_PASSWORD', 'password123');
    define('DB_HOST', 'proddb');
```
### Example
[Backup of wordpress configuration file found](https://hackerone.com/reports/33083)

[Searching for development files](https://github.com/tomnomnom/meg)

## Labs
Head over to folder `lib/vuln-node` and follow the setup instruction in the README.md file.

```
SQL Injection       | Section A1
Command Injection   | Section A1
IDOR                | Section - Section A4
Information Leakage | Section A6
```
