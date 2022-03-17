# FedBrokerScript

# Sample Config File
```
{
    "subDomain": "terraform-p2hub",
    "baseUrl": "oktapreview.com",
    "userName": "praveen.atluri@okta.com",
    "inputCsv": "input/group_assignments_batch2.csv"
}
```

## Commands to Run

## Usage

```
usage: OKTA_AppSignOnFromCSV_v1.py [-h] [--command "checkPolicy" or "backUpAndDelete" or "applyPolicy" or "enableFedBrokerMode" or "disableFedBrokerMode"] 
             [--ruleName "Enter Name of the rule to be created"] 
             [--groups "Enter Name groupsIds seperated by colon"] 
             [--network "InZone" or "NotInZone"] 
             [--includedNetworkZoneIds "enter in networkzone Ids seperated by colon"] 
             [--excludedNetworkZoneIds "enter out of networkzone Ids seperated by colon"] 
             [--action "DENY,ALLOW"] 
             [--mfa "ZERO,SESSION,ONE_DAY,ONE_WEEK,ONE_MONTH,SIX_MONTHS,FOREVER"]

optional arguments:
  -h, --help            show this help message and exit
  --command COMMAND     checkPolicy, backUpAndDelete, applyPolicy,  enableFedBrokerMode, disableFedBrokerMode 
  --network NETWORK     InZone, NotInZone
  --includedNetworkZoneIds INCLUDEDNETWORKZONEIDS
                        enter in networkzone Ids seperated by colon
  --excludedNetworkZoneIds EXCLUDEDNETWORKZONEIDS
                        enter out of networkzone Ids seperated by colon
  --mfa MFA             ZERO,SESSION,ONE_DAY,ONE_WEEK,ONE_MONTH,SIX_MONTHS,FOREVER
  --ruleName RULENAME   Enter Name of the rule to be created
  --groups GROUPS       Enter Name groupsIds seperated by colon
  --action ACTION       DENY,ALLOW
```
             
### help
```
python3 OKTA_AppSignOnFromCSV_v1.py -h
```

### Check if any App Sign On Policies Exist
```
python3 OKTA_AppSignOnFromCSV_v1.py --command checkPolicy
```

Above command checks if there is an existing app sign on policy. If policy exists, then it logs error in the "OKTA_AppSignOnFromCSV_v1.log" file

### Backup All Policies and Delete all the App Sign on Rules
```
python3 OKTA_AppSignOnFromCSV_v1.py --command backUpAndDelete
```

This command will delete all the app sign on Rules

### Add App Sign On Policy
```
python3 OKTA_AppSignOnFromCSV_v1.py --command applyPolicy
```

Above command checks if there is an existing app sign on policy and adds the app sign on policy. If policy exists, then it logs error in the "OKTA_AppSignOnFromCSV_v1.log" file and will not add new app sign on policy for the app.

### DENY RULE
```
python3 OKTA_AppSignOnFromCSV_v1.py --command applyPolicy --ruleName 'Deny|Everyone Else|Anywhere' --groups '00gqvhgkhsFIKVxqt0h7:00gnqbbuoaI59rA1a0h7' --action 'DENY'
```

### ALLOW RULE with Prompt for MFA

```
python3 OKTA_AppSignOnFromCSV_v1.py --command applyPolicy --ruleName 'promptforMFAWithIncludedNetworkZone' --groups '00gqvhgkhsFIKVxqt0h7:00gnqbbuoaI59rA1a0h7' --includedNetworkZoneIds 'nzox27fmdet7XNPEH0h7:nzox27d9mf0PVAZDe0h7'  --action 'ALLOW' --mfa ZERO
```

```
python3 OKTA_AppSignOnFromCSV_v1.py --command applyPolicy --ruleName 'promptforMFAWithExcludedNetworkZone' --groups '00gqvhgkhsFIKVxqt0h7:00gnqbbuoaI59rA1a0h7' --excludedNetworkZoneIds 'nzox27fmdet7XNPEH0h7:nzox27d9mf0PVAZDe0h7'  --action 'ALLOW' --mfa ZERO
```

### Enable Fed Broker Mode
```
python3 OKTA_AppSignOnFromCSV_v1.py --command enableFedBrokerMode
```

Above command will enable federation broker mode for app.

### Disable Fed Broker Mode
```
python3 OKTA_AppSignOnFromCSV_v1.py --command disableFedBrokerMode
```
