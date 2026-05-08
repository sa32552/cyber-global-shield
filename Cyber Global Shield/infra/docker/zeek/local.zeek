# Cyber Global Shield - Zeek Configuration v2.0 (Production-Grade)
# Network Security Monitor for real-time traffic analysis
# MITRE ATT&CK mapping, C2 detection, DGA analysis, file extraction

# ---- Logging Configuration ----
redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 10 min;
redef Log::default_rotation_postprocessor_cmd = "/usr/local/zeek/share/zeek/site/rotate_logs.sh";

# ---- Load Frameworks ----
@load frameworks/intel/seen
@load frameworks/intel/do_notice
@load frameworks/notice/weird
@load frameworks/notice/dp
@load frameworks/files/extract-all-files
@load frameworks/software/vulnerable
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/ssl/known-certs
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/ssh/geo-data
@load policy/protocols/http/detect-sqli
@load policy/protocols/http/detect-xss
@load policy/protocols/http/detect-webapps
@load policy/protocols/dns/detect-external-names
@load policy/frameworks/dpd/dpd
@load policy/frameworks/detect-protocols

# ---- Protocol Analyzers ----
redef Notice::ignored_types += { Site::NewVersion };

# ---- Detection Tuning ----

# Port Scan Detection (MITRE T1046)
redef Scan::sensitive_ports = {
    22/tcp, 23/tcp, 80/tcp, 443/tcp, 445/tcp,
    3389/tcp, 3306/tcp, 5432/tcp, 6379/tcp, 8080/tcp,
    8443/tcp, 9200/tcp, 27017/tcp, 11211/tcp, 25/tcp,
    53/tcp, 161/udp, 162/udp, 389/tcp, 636/tcp
};
redef Scan::suppress_scan_checks = F;
redef Scan::scan_threshold = 25;
redef Scan::max_scan_pps = 1000;

# Brute Force Detection (MITRE T1110)
redef SSH::password_guesses_limit = 30;
redef SSH::guess_accounts_limit = 5;
redef FTP::password_guesses_limit = 20;
redef FTP::guess_accounts_limit = 3;

# Long connection detection (C2 beaconing - MITRE T1071)
redef Conn::default_extract = T;
redef Conn::max_duration = 24 hrs;
redef Conn::max_threshold = 10000;

# File analysis
redef Files::enable_magic = T;
redef Files::enable_fingerprint = T;
redef Files::enable_md5 = T;
redef Files::enable_sha1 = T;
redef Files::enable_sha256 = T;

# SSL/TLS anomaly detection
redef SSL::disable_analyzer_after_detection = F;
redef SSL::notary_response_timeout = 30 sec;

# DNS anomaly detection (DGA - MITRE T1568)
redef DNS::max_query_length = 255;
redef DNS::max_queries_per_connection = 1000;

# ---- Intel Framework ----
redef Intel::read_files += {
    "/usr/local/zeek/share/zeek/site/intel.dat",
    "/usr/local/zeek/share/zeek/site/feodo.dat",
    "/usr/local/zeek/share/zeek/site/abuse_ch.dat"
};

# ---- Custom Notices ----

# C2 Beaconing Detection
event connection_state_remove(c: connection)
{
    if ( c$conn?$duration && c$conn$duration > 1 min &&
         c$conn$duration < 24 hrs &&
         c$conn$orig_bytes < 1000 &&
         c$conn$resp_bytes < 1000 )
    {
        NOTICE([
            $note=Weird::Activity,
            $msg=fmt("Potential C2 beacon: %s -> %s (%.1f bytes, %.1f sec)",
                     c$id$orig_h, c$id$resp_h,
                     c$conn$orig_bytes + c$conn$resp_bytes,
                     c$conn$duration),
            $conn=c,
            $identifier=cat(c$id$orig_h, c$id$resp_h),
            $suppress_for=1 hr
        ]);
    }
}

# DGA Detection via DNS entropy
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if ( |query| > 20 )
    {
        local entropy = 0.0;
        local char_counts: table[string] of count = table();
        for ( i in query )
        {
            local ch = sub_bytes(query, i, 1);
            if ( ch in char_counts )
                char_counts[ch] += 1;
            else
                char_counts[ch] = 1;
        }
        for ( ch, count in char_counts )
        {
            local p = count / |query|;
            entropy -= p * log10(p);
        }
        
        if ( entropy > 3.5 && qtype == 1 )  # A record
        {
            NOTICE([
                $note=DNS::High_Query_Entropy,
                $msg=fmt("Potential DGA domain: %s (entropy: %.2f)", query, entropy),
                $conn=c,
                $identifier=query,
                $suppress_for=1 hr
            ]);
        }
    }
}

# Data Exfiltration Detection (MITRE T1048)
event http_request(c: connection, method: string, original_uri: string,
                   unescaped_uri: string, version: string)
{
    if ( c$http?$request_body_len && c$http$request_body_len > 500000 )
    {
        NOTICE([
            $note=HTTP::Large_Request_Body,
            $msg=fmt("Large HTTP upload: %s -> %s (%d bytes)",
                     c$id$orig_h, c$id$resp_h, c$http$request_body_len),
            $conn=c,
            $identifier=cat(c$id$orig_h, c$id$resp_h),
            $suppress_for=1 hr
        ]);
    }
}

# Lateral Movement Detection (MITRE T1021)
event smb2_write_request(c: connection, hdr: SMB2::Header, file: SMB2::FileInfo, offset: count, length: count)
{
    if ( length > 1000000 )
    {
        NOTICE([
            $note=SMB::Large_Write,
            $msg=fmt("Large SMB write: %s -> %s (%d bytes to %s)",
                     c$id$orig_h, c$id$resp_h, length, file$name),
            $conn=c,
            $identifier=cat(c$id$orig_h, c$id$resp_h, file$name),
            $suppress_for=1 hr
        ]);
    }
}

# Ransomware Detection via file operations
event file_new(f: fa_file)
{
    if ( f?$mime_type && f$mime_type == "application/x-msdownload" )
    {
        if ( f?$conns )
        {
            for ( cid in f$conns )
            {
                local c = f$conns[cid];
                NOTICE([
                    $note=Files::Executable_Downloaded,
                    $msg=fmt("Executable downloaded: %s -> %s (%s)",
                             c$id$orig_h, c$id$resp_h, f$mime_type),
                    $conn=c,
                    $f=f,
                    $identifier=cat(c$id$orig_h, f$id),
                    $suppress_for=1 hr
                ]);
            }
        }
    }
}

# ---- Notice Policy ----
hook Notice::policy(n: Notice::Info)
{
    # Suppress noisy notices
    if (n$note in [Weird::Activity, PacketFilter::Compile_Pcap_Filter])
        break;

    # Escalate to alarm for high-severity
    if (n$note in [Scan::Port_Scan, SSH::Password_Guessing, DNS::High_Query_Entropy])
        add n$actions[Notice::ACTION_ALARM];
}

# ---- Performance ----
redef PacketFilter::enable_auto_high_multipath = T;
redef ignore_checksums = T;
redef max_events_per_second = 100000;
redef tcp_max_connections = 1000000;
