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
python3 OKTA_AppSignOnFromCSV_v1.py -h

### Check if any App Sign On Policies Exist
python3 OKTA_AppSignOnFromCSV_v1.py --command checkPolicy

---above command checks if there is an existing policy for the app. If policy exists, then it logs error in the "OKTA_AppSignOnFromCSV_v1.log" file

### Add App Sign On Policy
python3 OKTA_AppSignOnFromCSV_v1.py --command applyPolicy

### Enable Fed Broker Mode
python3 OKTA_AppSignOnFromCSV_v1.py --command enableFedBrokerMode

### Disable Fed Broker Mode
python3 OKTA_AppSignOnFromCSV_v1.py --command disableFedBrokerMode
