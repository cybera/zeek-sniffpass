# Sniffpass

[![Build Status](https://travis-ci.org/cybera/zeek-sniffpass.svg?branch=master)](https://travis-ci.org/cybera/zeek-sniffpass)

# Description
Sniffpass will alert on cleartext passwords discovered in HTTP POST requests.

By default it will not log passwords, but only log the username in a `post_username` field in `http.log`
 and create an entry in `notice.log` that a password was observed.

# Installation
- Install via Zeek package manager:
   ```bash
   $ zkg install zeek-sniffpass

   # or for legacy installs

   $ zkg install zeek-sniffpass
   ```
- Download the files to `$PREFIX/zeek/share/zeek/site/sniffpass` and add the following to your `local.zeek`:
    ```bash
    @load ./sniffpass
    ```

# Configuring
- You can enable different types of password logging. Add one (or more) of the following options to your `local.zeek` file:
    ```
    redef SNIFFPASS::log_password_plaintext = T;
    redef SNIFFPASS::log_password_md5 = T;
    redef SNIFFPASS::log_password_sha1 = T;
    redef SNIFFPASS::log_password_sha256 = T;
    ```
- You can disable logging to notice.log using this flag:
    ```
    redef SNIFFPASS::notice_log_enable = F;
    ```

- By default, only the first 300 bytes of an HTTP POST request are parsed. This can be changed by adding the following to your `local.zeek` file and setting your own value:
    ```
    redef SNIFFPASS::post_body_limit = 300
    ```

# Broker Support
Zeek can use Broker to publish discovered username and passwords. Each Zeek worker will connect to the `broker_host`. This can be useful in cases where credentials shouldn't be
saved to disk in a Zeek log file, but instead have them handled by a script. One use case of this is sending them to an API to retire valid credentials seen.

- Broker publishing is disabled by default, but can be enabled using these options:
    ```
    redef SNIFFPASS::broker_enable = T;
    redef SNIFFPASS::broker_host = "127.0.0.1";
    redef SNIFFPASS::broker_port = 9999/tcp;
    ```
- You can change the topic to something other than the default:
    ```
    redef SNIFFPASS::broker_topic = "/sniffpass/credentials_seen";
    ```
## Example Broker Python Script
This example was borrowed from the [Broker documentation](https://docs.zeek.org/projects/broker/en/lts/python.html)
```python
    import broker
    import sys

    # Setup endpoint and connect to Zeek.
    ep = broker.Endpoint()
    sub = ep.make_subscriber("/sniffpass/credentials_seen")
    ss = ep.make_status_subscriber(True);

    # Listen for connections from workers
    ep.listen("127.0.0.1", 9999)

    # Wait until connection is established.
    st = ss.get()

    if not (type(st) == broker.Status and st.code() == broker.SC.PeerAdded):
        print("could not connect")
        sys.exit(0)

    while True:
        (t, d) = sub.get()
        event = broker.zeek.Event(d)
        print("received {}{}".format(event.name(), event.args()))
```

Will give output like this when plaintext credentials are seen:
```
    $ python test_broker.py
    received SNIFFPASS::credentials_seen[u'my_username', u'Thi1sI$myP@ssw0rd']
```

## Detailed Broker Output
There is an option to also include Destination IP, Destination Port, and full URL in the Broker output.

You can enable a more detailed output in Broker:

    redef SNIFFPASS::broker_detailed = T;

The output from the Example Python Script:

    $ python test_broker.py
    received SNIFFPASS::credentials_seen_detailed[(u'my_username', u'Thi1sI$myP@ssw)rd'), IPv4Address(u'127.0.0.1'), 80/tcp, u'localhost/']

# Automated Testing
Automated tests are done against the `http_post.trace` file with Travis CI.

# Troubleshooting
- If you are having any issues, ensure that you have TCP Checksumming disabled in your `local.zeek` file, as per [Zeek Documentation](https://www.zeek.org/documentation/faq.html#why-isn-t-zeek-producing-the-logs-i-expect-a-note-about-checksums)

    ```
    redef ignore_checksums = T;
    ```

# Created By
Andrew Klaus (Cybera)

_This module was inspired by the University of Alberta's 2019 CUCCIO Innovation Award Plaintext Password Sniffing Project._
