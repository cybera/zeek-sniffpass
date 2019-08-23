# Description
Sniffpass will alert on cleartext passwords discovered in HTTP POST requests.

By default it will not log passwords, but only log the username in a `post_username` field in `http.log`
 and create an entry in `notice.log` that a password was observed.

# Installation
- Install via Zeek package manager:
   ```bash
   $ zkg install zeek-sniffpass

   # or for legacy installs

   $ bro-pkg install zeek-sniffpass
   ```
- Download the files to `$PREFIX/bro/share/bro/site/sniffpass` and add the following to your `local.bro`:
    ```bash
    @load ./sniffpass
    ```

# Configuring
- You can enable different types of password logging. Add one (or more) of the following options to your `local.bro` file:
    ```
    redef SNIFFPASS::log_password_plain = T;
    redef SNIFFPASS::log_password_md5 = T;
    redef SNIFFPASS::log_password_sha1 = T;
    redef SNIFFPASS::log_password_sha256 = T;
    ```
- You can disable logging to notice.log using this flag:
    ```
    redef SNIFFPASS::notice_log_enable = F;
    ```

- By default, only the first 300 bytes of an HTTP POST request are parsed. This can be changed by adding the following to your `local.bro` file and setting your own value:
    ```
    redef SNIFFPASS::post_body_limit = 300
    ```

# Testing
There are `curl` command examples inside `tests/curl.sh` that can be used to check if Zeek is properly parsing HTTP POST requests.

# Troubleshooting
- If you are having any issues, ensure that you have TCP Checksumming disabled in your `local.bro` file, as per [Zeek Documentation](https://www.zeek.org/documentation/faq.html#why-isn-t-zeek-producing-the-logs-i-expect-a-note-about-checksums)

    ```
    redef ignore_checksums = T;
    ```

# Created By
Andrew Klaus (Cybera)

_This module was inspired by the University of Alberta's 2019 CUCCIO Innovation Award Plaintext Password Sniffing Project._
