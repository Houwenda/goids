# goids
homework of network programming course

config file [example](https://github.com/Houwenda/goids/blob/master/config/goids.yaml):
```yaml
ui:
    enable: true
    ip: "localhost"
    port: 3690
    location: "abcd"
    db_path: "/path/to/your/db.csv"
rules:
    pkt_rules: ["/path/to/your/pkt_rules.rules"]
    stream_rules: ["/path/to/your/stream_rules.rules"]
analyzer:
    max_proc: 4
    group_num: 1
    strict_mode:
        enable: true
        worker_num: 1
    interfaces: ["wlan0"]
log:
    # level: debug, production
    path: "/path/to/your/goids.log"
    level: "debug"
alarm:
    mail:
        enable: false
        max_freq: 300
        server_address: "smtp.example.com"
        username: "noreply@example.com"
        auth_key: ""
        receivers: ["example@gmail.com"]
    json_file:
        # level: log alert
        enable: false
        level: log
        path: "/path/to/your/json_log.json"
    scripts: []
    db_path: "/path/to/your/db.csv"
```

packet rule example:
```
log tcp 2002:0:0:0:0:0:c000:1 25:30 -> any 25:31 (msg:"FILE-IDENTIFY Portable Executable binary file magic detected"; content:!"PE|ab 00|"; within:4; distance:-64; protected_content:!"56D6F32151AD8474F40D7B939C2161EE2BBF10023F4AF1DBB3E13260EBDC6342"; offset:1; length:4; hash:sha256;  metadata:policy balanced-ips alert, policy connectivity-ips alert, policy max-detect-ips drop, policy security-ips alert, ruleset community, service smtp; classtype:misc-activity; sid:52056; rev:1;)
stream udp any 54915 -> 192.168.0.255 54915 (msg:"LCore.exe from logitech driver 'Logitech Game Software' udp broadcasts detected"; content:"MSI|00 00 00 00|"; offset:1; distance:10; content:"{a0e8a3bd-21e7-4ed6-b386-f91e27dfbf72}"; classtype:misc-activity; metadata:policy specific-device-driver log; metadata:policy specific-driver-activity alert; reference:https://github.com/Houwenda; sid:5205601)
```

stream rule example:
```
action:alert; sid:5205601; minute:2
```
