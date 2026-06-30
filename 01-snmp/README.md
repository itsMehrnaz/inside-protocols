# Inside SNMP: From Packets to Rust

Part 1 of the **Inside Protocols** series — Theory → Packet → Attack → Code → Lab.

Full article: 

## Lab setup

Without Docker (recommended):

```bash
sudo apt install -y snmpd snmp
echo "rocommunity public  localhost" | sudo tee /etc/snmp/snmpd.conf
echo "sysName MyLabAgent" | sudo tee -a /etc/snmp/snmpd.conf
sudo systemctl restart snmpd
```

With Docker:

```bash
docker compose up -d
```

Test:

```bash
snmpget -v2c -c public localhost 1.3.6.1.2.1.1.5.0
```

## Run the Rust SNMP GET

```bash
cd snmp-get
cargo run
```

You should see `sysName = MyLabAgent`.
