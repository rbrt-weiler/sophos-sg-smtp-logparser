# Sophos SG SMTP Logfile Parser (SSSLP) Performance

In order to get a hold of how well SSSLP performs, I ran a simple test suite. Short story: SSSLP performs well even for large logfiles.

## Sample Logfiles

For my tests, I constructed the following logfile, which mimics how an incoming mail is processed in a real logfile.

```text
2020:07:18-16:56:31 some-sg exim-in[24020]: logfoo P=esmtp
2020:07:18-16:56:31 some-sg smtpd[4020]: QMGR[4020]: logfoo moved to work queue
2020:07:18-16:56:31 some-sg smtpd[14020]: SCANNER[14020]: logfoo P=INPUT
2020:07:18-16:56:31 some-sg smtpd[14020]: SCANNER[14020]: id="1000" severity="info" sys="SecureMail" sub="smtp" name="email passed" srcip="10.1.2.3" from="someone@example.com" to="someone@else.example.com" subject="Some e-mail conversation" queueid="1abCdE-0a6b1f-A4" size="587538"
2020:07:18-16:56:31 some-sg smtpd[14020]: SCANNER[14020]: logfoo T=SCANNER
2020:07:18-16:56:31 some-sg smtpd[14020]: SCANNER[14020]: logfoo Completed
2020:07:18-16:56:31 some-sg exim-out[1420]: logfoo T=static_smtp
2020:07:18-16:56:31 some-sg exim-out[1420]: logfoo Completed
2020:07:18-16:56:31 some-sg exim-in[24021]: logfoo P=esmtp
2020:07:18-16:56:31 some-sg smtpd[4021]: QMGR[4021]: logfoo moved to work queue
2020:07:18-16:56:31 some-sg smtpd[14021]: SCANNER[14021]: logfoo P=INPUT
2020:07:18-17:12:15 some-sg smtpd[14021]: SCANNER[14021]: id="1000" severity="info" sys="SecureMail" sub="smtp" name="email passed" srcip="10.1.2.3" from="someone@else.example.com" to="someone@example.com" subject="Re: Some e-mail conversation" queueid="1abCdE-57b8f1-A5" size="89465"
2020:07:18-16:56:31 some-sg smtpd[14021]: SCANNER[14021]: logfoo T=SCANNER
2020:07:18-16:56:31 some-sg smtpd[14021]: SCANNER[14021]: logfoo Completed
2020:07:18-16:56:31 some-sg exim-out[1421]: logfoo T=static_smtp
2020:07:18-16:56:31 some-sg exim-out[1421]: logfoo Completed
2020:07:18-16:56:31 some-sg exim-in[24022]: logfoo P=esmtp
2020:07:18-16:56:31 some-sg smtpd[4022]: QMGR[4022]: logfoo moved to work queue
2020:07:18-16:56:31 some-sg smtpd[14022]: SCANNER[14022]: logfoo P=INPUT
2020:07:18-17:14:29 some-sg smtpd[14022]: SCANNER[14022]: id="1000" severity="info" sys="SecureMail" sub="smtp" name="email passed" srcip="10.1.2.3" from="someone@outside.example.com" to="someone@example.com" subject="Just letting you know" queueid="1abCdE-2baf9d-A6" size="56264"
2020:07:18-16:56:31 some-sg smtpd[14022]: SCANNER[14022]: logfoo T=SCANNER
2020:07:18-16:56:31 some-sg smtpd[14022]: SCANNER[14022]: logfoo Completed
2020:07:18-16:56:31 some-sg exim-out[1422]: logfoo T=static_smtp
2020:07:18-16:56:31 some-sg exim-out[1422]: logfoo Completed
```

The file above consists of 23 lines, from which 3 are actually relevant for SSSLP. In order to create larger logfiles I concatenated the file above into new files for 10, 100, 1.000, 10.000 and 100.000 times.

| File | Lines Total | Relevant Lines | Bytes |
| --- | ---:| ---:| ---:|
| sophos-sg-smtp-000003.log | 23 | 3 | 2.334 |
| sophos-sg-smtp-000030.log | 230 | 30 | 23.340 |
| sophos-sg-smtp-000300.log | 2.300 | 300 | 233.400 |
| sophos-sg-smtp-003000.log | 23.000 | 3.000 | 2.334.000 |
| sophos-sg-smtp-030000.log | 230.000 | 30.000 | 23.340.000 |
| sophos-sg-smtp-300000.log | 2.300.000 | 300.000 | 233.400.000 |

## Test Procedure

To measure performance, I ran the following shell script. It measures the runtime for five times, both for CSV and JSON output, but without writing SSSLP output to disk.

```bash
#!/bin/bash

SSSLP="./SSSLP -i example.com"

for FILE in `ls *.log` ; do
    $SSSLP --version
    LINES="`wc -l $FILE | cut -d' ' -f1`"
    RELEVANTLINES="`grep severity $FILE | wc -l`"
    echo "File <$FILE> with <$RELEVANTLINES> relevant out of <$LINES> total lines:"
    echo "CSV mode:"
    for COUNT in {1..5} ; do
        echo "Run $COUNT:"
        time $SSSLP $FILE | grep -E '^(real|user|sys)'
        echo
    done
    echo "JSON mode:"
    for COUNT in {1..5} ; do
        echo "Run $COUNT:"
        time $SSSLP -J $FILE | grep -E '^(real|user|sys)'
        echo
    done
    echo
    echo
done
```

## Results

### 2020-Jul-19, v1.0.0

I ran the test on Jul 19th, 2020 on a shared server. 6-Core Xeon Gold 6140, 32 GB RAM and SSD-based storage as dedicated (by means of KVM) ressources. Running on 50% base CPU load due to other services. Fedora 31 with SSSLP v1.0.0.

Worst CSV mode results:

| File | Real | User | Sys |
| --- | ---:| ---:| ---:|
| sophos-sg-smtp-000003.log | 0m0.003s | 0m0.002s | 0m0.004s |
| sophos-sg-smtp-000030.log | 0m0.005s | 0m0.005s | 0m0.003s |
| sophos-sg-smtp-000300.log | 0m0.017s | 0m0.016s | 0m0.005s |
| sophos-sg-smtp-003000.log | 0m0.186s | 0m0.174s | 0m0.022s |
| sophos-sg-smtp-030000.log | 0m1.509s | 0m1.501s | 0m0.070s |
| sophos-sg-smtp-300000.log | 0m14.582s | 0m14.797s | 0m0.493s |

JSON mode results:

| File | Real | User | Sys |
| --- | ---:| ---:| ---:|
| sophos-sg-smtp-000003.log | 0m0.004s | 0m0.002s | 0m0.005s |
| sophos-sg-smtp-000030.log | 0m0.005s | 0m0.005s | 0m0.003s |
| sophos-sg-smtp-000300.log | 0m0.022s | 0m0.021s | 0m0.005s |
| sophos-sg-smtp-003000.log | 0m0.255s | 0m0.237s | 0m0.029s |
| sophos-sg-smtp-030000.log | 0m1.993s | 0m1.956s | 0m0.183s |
| sophos-sg-smtp-300000.log | 0m17.839s | 0m17.124s | 0m1.917s |
