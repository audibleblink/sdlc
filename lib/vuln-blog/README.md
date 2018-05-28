# Vuln-Blog

This intentionaly vulnerable web application allows attacker to execute social engineering attacks
against an admin user.

Attackers may create posts which they can send to an admin user, who will open the link.

The Admin will also following links to servers that you control. Try to see if you can force an
admin to conduct an action on your behalf.

The search option refelcts queries to the browser. See if you can steal the admin's session.

## Starting the vulnerable application

The application is dockerized for your convenience. Run the following commands to get the server up
and running locally.

```sh
sudo docker build -t vuln-server .
sudo docker run --rm -p 4567:4567 -v ${PWD}:/app vuln-blog
```

## Getting Started
Your hacker's logon credentials are `dade:zeroc00l`. Use the 'support' button at the bottom of the
page to launch any social engineering attacks.

1. Steal an admin's session using XSS on the site's Search feature
2. Attempt to post an article as the admin using XSRF

To log out or reset the database to its initial state, click the 'Reset' button at the bottom of
any page.
