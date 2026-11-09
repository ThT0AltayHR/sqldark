# SQLDark

Advanced SQL injection & database takeover framework. A modern, modular
alternative to legacy tools: fast, WAF-aware, and built to adapt.

> Use only on systems you own or are explicitly authorized to test.

## Install

```
pip install .
```

## Usage

```
sqldark -u "http://target/page.php?id=1"
sqldark -u "http://target/page.php?id=1" --tamper space2comment,randomcase
sqldark -u "http://target/login" --data "user=a&pass=b"
sqldark --list-tampers
```
