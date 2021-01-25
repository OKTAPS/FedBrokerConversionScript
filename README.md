# JD-FedBrokerScript

# Sample Config File
{
    "subDomain": "terraform-p2hub",
    "baseUrl": "oktapreview.com",
    "userName": "praveen.atluri@okta.com",
    "inputCsv": "input/jd_group_assignments_batch2.csv"
}

## Commands to Run

### Check if any App Sign On Policies Exist
python3 OKTA_AppSignOnFromCSV_v1.py --command checkPolicy

### Add App Sign On Policy
python3 OKTA_AppSignOnFromCSV_v1.py --command applyPolicy

### Enable Fed Broker Mode
python3 OKTA_AppSignOnFromCSV_v1.py --command enableFedBrokerMode

### Disable Fed Broker Mode
python3 OKTA_AppSignOnFromCSV_v1.py --command disableFedBrokerMode
