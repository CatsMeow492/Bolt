# Bolt 10.10.11.114

Core Concepts:

- SSTI
- Password Reuse
- PGP Private Key Cracking

## Enumeration

As is tradion let's get started with an nmap scan
```
nmap -sV -sC 10.10.11.114 -o nmap.bolt.txt
```
nmap reveals 3 open ports; 22, 80 and 442.  22 is ssh and 80 indicates the victim is likely hosting a webserver. 443 I'm unfamiliar with at first glance.
The typical route at this point is to sick gobuster on the webserver.
```
wget https://raw.githubusercontent.com/digination/dirbuster-ng/master/wordlists/common.txt
gobuster dir -u 10.10.11.114 -w common.txt -o gobuster.bolt.txt
```
> Output
```
/contact              (Status: 200) [Size: 26293]
/download             (Status: 200) [Size: 18570]
/index                (Status: 308) [Size: 247] [--> http://10.10.11.114/]
/login                (Status: 200) [Size: 9287]
/logout               (Status: 302) [Size: 209] [--> http://10.10.11.114/]
/pricing              (Status: 200) [Size: 31731]
/profile              (Status: 500) [Size: 290]
/register             (Status: 200) [Size: 11038]
/services             (Status: 200) [Size: 22443]
```
The /login page and /contact page likely have some potential. Anything that has a post method tends to be vulnerable to attacks. And whenever we have some kind of input field we likely have an injectrion vector.

![Login Page](2021-12-06_11-15.png)

We have two choices here; bruteforce some login creds or enumerate more. In real life we're going to want to spend as much time enumerating our attack vectors as possible. Brute forcing always runs the risk of raising some red flags with the victim.

![Download Link](2021-12-06_11-24.png)

Browsing back to the landing page we see there's actual a menu link for downloading a tar of the website.  Let's check it out!

![Downlaod](2021-12-06_11-25.png)
