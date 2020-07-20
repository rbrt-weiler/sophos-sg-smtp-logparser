# Sophos SG SMTP Logfile Parser (SSSLP)

Sophos SG SMTP Logfile Parser - SSSLP - parses a number of [Sophos SG (UTM)](https://www.sophos.com/en-us/products/unified-threat-management.aspx) SMTP logfiles (uncompressed or gzip'ed) and provides an overview of the e-mails sent and received. The result is printed to stdout in two formats:

* CSV (the default) provides a CSV-styled list of communication partners and their associated mail volume (count and bytes). It is intended to give administrators a quick overview of the mail traffic.
* JSON provides a very detailed representation of the e-mails sent between communication partners. It is intended to be used by another program.

SSSLP aims to help administrators who are requested to analyze e-mail traffic. It is [fast enough](PERFORMANCE.md) to handle even large logfiles with ease.

## Usage

`SSSLP -h`:

```text
Available options:
  -i, --internalhost string   Host part to be considered as internal
  -J, --json                  Output in JSON format
      --no-csv-header         Omit CSV header line
  -o, --outfile string        File to write data to instead of stdout
      --version               Print version information and exit
```

### Exit Codes

* 0: Success
* 1: Usage message was shown
* 10: Outfile could not be created
* 11: Outfile could not be written to
* 12: Outfile could not be synced to disk

## Output Formats

Given the following logfile, stored as `mail.log`:

```text
2020:07:18-16:56:31 some-sg smtpd[14020]: SCANNER[14020]: id="1000" severity="info" sys="SecureMail" sub="smtp" name="email passed" srcip="10.1.2.3" from="someone@example.com" to="someone@else.example.com" subject="Some e-mail conversation" queueid="1abCdE-0a6b1f-A4" size="587538"
2020:07:18-17:12:15 some-sg smtpd[14021]: SCANNER[14021]: id="1000" severity="info" sys="SecureMail" sub="smtp" name="email passed" srcip="10.1.2.3" from="someone@else.example.com" to="someone@example.com" subject="Re: Some e-mail conversation" queueid="1abCdE-57b8f1-A5" size="89465"
2020:07:18-17:14:29 some-sg smtpd[14022]: SCANNER[14022]: id="1000" severity="info" sys="SecureMail" sub="smtp" name="email passed" srcip="10.1.2.3" from="someone@outside.example.com" to="someone@example.com" subject="Just letting you know" queueid="1abCdE-2baf9d-A6" size="56264"
```

### CSV

Running `SSSLP -i example.com mail.log` will result in this output:

```csv
type,sizeAtoB,countAtoB,partnerA,partnerB,countBtoA,sizeBtoA,isTwoWay
e2i,89465,1,someone@else.example.com,someone@example.com,1,587538,true
i2e,0,0,someone@example.com,someone@outside.example.com,1,56264,false
```

* `type` defines the type of communication. It may be "i2i", "i2e", "e2i" or "e2e". In each case, "i" stands for internal and "e" stand for external.
* `sizeAtoB` is the amount of bytes sent from partner A to partner B.
* `countAtoB` is the number of mails sent from partner A to partner B.
* `partnerA` is the e-mail address of partner A.
* `partnerB` is the e-mail address of partner B.
* `countBtoA` is the number of mails sent from partner B to partner A.
* `sizeBtoA` is the amount of bytes sent from partner B to partner A.
* `isTwoWay` is true if `countAtoB` and `countBtoA` both is greater than 0, else false.

### JSON

JSON output is more complex and detailed than CSV output. Running `SSSLP -i example.com -J mail.log` will results in this output:

```json
{
    "createDateTime": "2020-07-18T17:16:25.3616237+02:00",
    "createDateTimeUnix": 1595085385,
    "createDate": "2020-07-18",
    "createTime": "17:16:25",
    "partners": {
        "someone@else.example.com someone@example.com": {
            "partnerA": "someone@else.example.com",
            "userA": "someone",
            "hostA": "else.example.com",
            "typeA": "external",
            "partnerB": "someone@example.com",
            "userB": "someone",
            "hostB": "example.com",
            "typeB": "internal",
            "type": "e2i",
            "mailsTotal": 2,
            "sizeTotal": 677003,
            "mailsAtoB": 1,
            "sizeAtoB": 89465,
            "mailsBtoA": 1,
            "sizeBtoA": 587538,
            "isTwoWay": true,
            "mails": [
                {
                    "mailID": "40f9f9ad7621fea1a7a326ca23098e896c08fd63acf44ce62a746f77395bda1c",
                    "queueID": "1abCdE-0a6b1f-A4",
                    "date": "2020-07-18",
                    "time": "16:56:31",
                    "from": "someone@example.com",
                    "hostFrom": "example.com",
                    "userFrom": "someone",
                    "typeFrom": "internal",
                    "to": "someone@else.example.com",
                    "hostTo": "else.example.com",
                    "userTo": "someone",
                    "typeTo": "external",
                    "size": 587538,
                    "subject": "Some e-mail conversation"
                },
                {
                    "mailID": "5d8e8fe3559ff0e95869375a708344f2114942ad4954bdc6d11cce1ce0bd8a39",
                    "queueID": "1abCdE-57b8f1-A5",
                    "date": "2020-07-18",
                    "time": "17:12:15",
                    "from": "someone@else.example.com",
                    "hostFrom": "else.example.com",
                    "userFrom": "someone",
                    "typeFrom": "external",
                    "to": "someone@example.com",
                    "hostTo": "example.com",
                    "userTo": "someone",
                    "typeTo": "internal",
                    "size": 89465,
                    "subject": "Re: Some e-mail conversation"
                }
            ]
        },
        "someone@example.com someone@outside.example.com": {
            "partnerA": "someone@example.com",
            "userA": "someone",
            "hostA": "example.com",
            "typeA": "internal",
            "partnerB": "someone@outside.example.com",
            "userB": "someone",
            "hostB": "outside.example.com",
            "typeB": "external",
            "type": "i2e",
            "mailsTotal": 1,
            "sizeTotal": 56264,
            "mailsAtoB": 0,
            "sizeAtoB": 0,
            "mailsBtoA": 1,
            "sizeBtoA": 56264,
            "isTwoWay": false,
            "mails": [
                {
                    "mailID": "e5e5b11df4fdc29d903f128dd8a8e6aea6ecb1f1ef5b49ca3cf1bacf1c5518e1",
                    "queueID": "1abCdE-2baf9d-A6",
                    "date": "2020-07-18",
                    "time": "17:14:29",
                    "from": "someone@outside.example.com",
                    "hostFrom": "outside.example.com",
                    "userFrom": "someone",
                    "typeFrom": "external",
                    "to": "someone@example.com",
                    "hostTo": "example.com",
                    "userTo": "someone",
                    "typeTo": "internal",
                    "size": 56264,
                    "subject": "Just letting you know"
                }
            ]
        }
    }
}
```

## Dependencies

This tool uses Go modules to handle dependencies. If you cannot use Go modules, please run the following commands to fetch dependencies:

1. `go get -u github.com/spf13/pflag`

## Running / Compiling

Use `go run ./...` to run the tool directly or `go build -o SSSLP ./...` to compile a binary. Prebuilt binaries may be available as artifacts from the GitLab CI/CD [pipeline for tagged releases](https://gitlab.com/rbrt-weiler/sophos-sg-smtp-logparser/pipelines?scope=tags).

Tested with [go1.14](https://golang.org/doc/go1.14).

## Source

The original project is [hosted at GitLab](https://gitlab.com/rbrt-weiler/sophos-sg-smtp-logparser), with a [copy over at GitHub](https://github.com/rbrt-weiler/sophos-sg-smtp-logparser) for the folks over there.
