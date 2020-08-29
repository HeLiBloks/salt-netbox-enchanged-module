# salt-netbox-enchanged-module
Add salt minions to netbox


## prerequisites
add configuration to pillar or /etc/salt/minion
```yaml
netbox:
  url: http://netbox-server/api/
  token:  97966605def45f2adae9903e3f4e97365e8faab4
```

## Usage
Add a minion and its current network configuration
```bash
salt '*' netboxen.vm_add introspect=True cluster=delta
salt '*' netboxen.interface_add introspect=True
salt '*' netboxen.ipaddress_add introspect=True
```
