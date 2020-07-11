# Sophos SMTP Logparser

## Preliminary notes

How the logfile is constructed: https://community.sophos.com/products/unified-threat-management/f/mail-protection-smtp-pop3-antispam-and-antivirus/114272/how-to-analyze-the-smtp-log-file

Sample log line:  
`2019:06:10-11:04:43 defense smtpd[9095]: SCANNER[9095]: id="1000" severity="info" sys="SecureMail" sub="smtp" name="email passed" srcip="ip1.ip2.ip3.ip4" from="sendinguser@senderdomain.tld" to="targetuser@targetdomain.tld" subject="Statement" queueid="1haLql-0002Mh-MA" size="63168"`

Internal data structure:

```json
{
    "user@hostA user@hostB": {
        "queueIDX": {
            "date": "2006-01-02",
            "time": "15:34:56",
            "mailFrom": "user@hostA",
            "hostFrom": "hostA",
            "userFrom": "user",
            "typeFrom": "internal",
            "mailTo": "user@hostB",
            "hostTo": "hostB",
            "userTo": "user",
            "typeTo": "external",
            "mailSize": 12345,
            "subject": "Lorem ipsum"
        },
        "queueIDY": {
            "date": "2006-01-02",
            "time": "16:34:56",
            "mailFrom": "user@hostB",
            "hostFrom": "hostB",
            "userFrom": "user",
            "typeFrom": "external",
            "mailTo": "user@hostA",
            "hostTo": "hostA",
            "userTo": "user",
            "typeTo": "internal",
            "mailSize": 678,
            "subject": "Re: Lorem ipsum"
        },
        "queueIDZ": {
            "date": "2006-01-02",
            "time": "17:34:56",
            "mailFrom": "user@hostA",
            "hostFrom": "hostA",
            "userFrom": "user",
            "typeFrom": "internal",
            "mailTo": "user@hostB",
            "hostTo": "hostB",
            "userTo": "user",
            "typeTo": "external",
            "mailSize": 9012,
            "subject": "Re: Re: Lorem ipsum"
        }
    },
    "user@hostA user@hostC": {
        "queueIDP": {
            "date": "2006-01-03",
            "time": "14:34:56",
            "mailFrom": "user@hostA",
            "hostFrom": "hostA",
            "userFrom": "user",
            "typeFrom": "internal",
            "mailTo": "user@hostC",
            "hostTo": "hostC",
            "userTo": "user",
            "typeTo": "external",
            "mailSize": 34567,
            "subject": "Dolor sit amet"
        }
    }
}
```

Key "user@hostA user@hostC" is sorted by host part; if the hosts are equal, the key is sorted by full address.

CLI arguments:

* `logfile "filename"`: logfile to parse; can be defined multiple times
* `internalhost "string"`: host part that shall be interpreted as internal; can be defined multiple times
* `outfileCSV "filename"`: file to store CSV output
* `outfileXLSX "filename"`: file to store XLSX output
* `outfileJSON "filename"`: file to store JSON output
* `delimiter "string"`: delimiter to use in CSV output; defaults to ","
* `compress`: if set, CSV and JSON output will be gzip compressed

CSV output limited to "type,fromA,mailA,mailB,fromB", where type is "i2i", "i2e", "e2i" or "e2e". Sorted by mailA.  
XLSX output will probable contain the same information as CSV. Depends on testing.  
JSON output will contain the whole data structure, so that follow up code can work with it.
