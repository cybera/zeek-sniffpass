@load base/protocols/http
@load base/frameworks/notice

module SNIFFPASS;

global username_fields = set("USERNAME", "USRNAME", "UNAME", "EMAIL", "USER", "USR", "LOGIN", "NAME", "AUTH", "LOG");
global password_fields = set("PASSWORD", "PASS", "PSW", "PWD", "SECRET");


type Credential: record {
    username: string;
    password: string;
};

global credentials_seen: event(cred: Credential);
global credentials_seen_detailed: event(cred: Credential, dest_ip: addr, dest_port: port, url :string);

export {
    const log_username = T &redef;
    const log_password_plaintext = F &redef;
    const log_password_md5 = F &redef;
    const log_password_sha1 = F &redef;
    const log_password_sha256 = F &redef;
    const post_body_limit = 300 &redef;
    const notice_log_enable = T &redef;
    const broker_enable = F &redef;
    const broker_host = "127.0.0.1" &redef;
    const broker_port = 9999/tcp &redef;
    const broker_topic = "/sniffpass/credentials_seen" &redef;
    const broker_detailed = F &redef;
}

type SPStorage: record {
    inspect_post_data: bool &default=F &log;
    post_data: string &log &optional;
};

redef record HTTP::Info += {
    post_username: string &log &optional;
    post_password_plain: string &log &optional;
    post_password_md5: string &log &optional;
    post_password_sha1: string &log &optional;
    post_password_sha256: string &log &optional;
};

redef enum Notice::Type += {
    HTTP_POST_Password_Seen,
};

redef record connection += {
    sp: SPStorage &optional;
};

function cred_handler(cred: Credential, c: connection)
{
    if ( SNIFFPASS::broker_detailed )
    {
        local dest_ip = c$id$resp_h;
        local dest_port = c$id$resp_p;
        local url = c$http$host + c$http$uri;
        event SNIFFPASS::credentials_seen_detailed(cred, dest_ip, dest_port, url);
    }
    else
    {
        event SNIFFPASS::credentials_seen(cred);
    }
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if ( is_orig && c$http$method == "POST") {
        if (to_upper(name) == "CONTENT-TYPE"
            && to_upper(value) == "APPLICATION/X-WWW-FORM-URLENCODED")
        {
            if ( ! c?$sp )
                c$sp = SPStorage();

            c$sp$inspect_post_data = T;
            c$sp$post_data = "";
    }
  }
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
  {
    if ( is_orig && c?$sp && c$sp$inspect_post_data ) {
        if ( |c$sp$post_data| >= post_body_limit )
            return;

        c$sp$post_data += data;

        if ( |c$sp$post_data| > post_body_limit )
            c$sp$post_data = c$sp$post_data[0:post_body_limit] + "~";
    }
  }

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
    if ( is_orig && c?$sp && c$sp$inspect_post_data )
    {
        local post_parsed = split_string(c$sp$post_data, /&/);
        local password_seen = F;
        local username_value = "";
        local password_value = "";

        for (p in post_parsed) {
            local kv = split_string1(post_parsed[p], /=/);
            if (to_upper(kv[0]) in username_fields) {
                username_value = kv[1];
                c$http$post_username = username_value;
            }
            if (to_upper(kv[0]) in password_fields) {
                password_value = kv[1];
                password_seen = T;

                if ( log_password_plaintext )
                    c$http$post_password_plain = password_value;
                if ( log_password_md5 )
                    c$http$post_password_md5 = md5_hash(password_value);
                if ( log_password_sha1 )
                    c$http$post_password_sha1 = sha1_hash(password_value);
                if ( log_password_sha256 )
                    c$http$post_password_sha256 = sha256_hash(password_value);
            }
        }

        if ( password_seen ) {
            if ( |username_value| > 0 )
            {
                local cred = Credential($username = username_value, $password = password_value);
                cred_handler(cred, c);

                if (notice_log_enable) {
                    NOTICE([$note=HTTP_POST_Password_Seen,
                    $msg="Password found for user " + username_value,
                    $conn=c ]);
                }
            }
            else
            {
                if (notice_log_enable) {
                    NOTICE([$note=HTTP_POST_Password_Seen,
                    $msg="Password found",
                    $conn=c ]);
                }
            }
        }
    }
}

event zeek_init()
{
    # Only use Broker if it's available
    @ifdef (Broker::auto_publish)
        if (SNIFFPASS::broker_enable)
        {
            # When in cluster mode, only workers should connect to broker_host
            if ( (Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER ) || ! Cluster::is_enabled() ) {
                Broker::peer(SNIFFPASS::broker_host, SNIFFPASS::broker_port);
                Broker::auto_publish(SNIFFPASS::broker_topic, SNIFFPASS::credentials_seen);
                Broker::auto_publish(SNIFFPASS::broker_topic, SNIFFPASS::credentials_seen_detailed);
            }
        }
    @endif
}
