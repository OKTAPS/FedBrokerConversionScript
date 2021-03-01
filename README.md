# JD-FedBrokerScript

# Sample Config File
{
    "subDomain": "terraform-p2hub",
    "baseUrl": "oktapreview.com",
    "userName": "praveen.atluri@okta.com",
    "inputCsv": "input/jd_group_assignments_batch2.csv"
}

## Commands to Run

### help
## python3 OKTA_AppSignOnFromCSV_v1.py -h

### Check if any App Sign On Policies Exist
## python3 OKTA_AppSignOnFromCSV_v1.py --command checkPolicy

Above command checks if there is an existing app sign on policy. If policy exists, then it logs error in the "OKTA_AppSignOnFromCSV_v1.log" file

### Back All Policies and Delete all the App Sign on Rules
## python3 OKTA_AppSignOnFromCSV_v1.py --command backUpAndDelete

This command will delete all the app sign on Rules

### Add App Sign On Policy
## python3 OKTA_AppSignOnFromCSV_v1.py --command applyPolicy

Above command checks if there is an existing app sign on policy and adds the app sign on policy. If policy exists, then it logs error in the "OKTA_AppSignOnFromCSV_v1.log" file and will not add new app sign on policy for the app.

## python3 OKTA_AppSignOnFromCSV_v1.py --command applyPolicy --ruleName 'Deny|Everyone Else|Anywhere' --groups '00gqvhgkhsFIKVxqt0h7:00gnqbbuoaI59rA1a0h7' --action 'DENY'

### Enable Fed Broker Mode
python3 OKTA_AppSignOnFromCSV_v1.py --command enableFedBrokerMode

Above command will enable federation broker mode for app.

### Disable Fed Broker Mode
python3 OKTA_AppSignOnFromCSV_v1.py --command disableFedBrokerMode
