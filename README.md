# snmp_cplus_lib

# 测试 使用 IReasoning MIB Browser  

```
模拟 localhost,v1,OID 为 .1.3.6.1.2.1.1.5.0 的get请求 （system 下的 sysName)

返回 Name/OID: sysName.0; Value (OctetString): Simple SNMP Agent v1.0
```

## 测试使用 snmpget

```
$ snmpget -v1 -c public localhost system.sysName
SNMPv2-MIB::sysName.0 = STRING: Simple SNMP Agent v1.0
```