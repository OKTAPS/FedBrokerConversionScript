#!/Library/Frameworks/Python.framework/Versions/3.8/bin/python3
import csv
import os
import json
import requests
import sys, getopt
import re
from bs4 import BeautifulSoup
import getpass
import logging
import argparse
from collections import OrderedDict

result = {}
appList = {}
jsonObjToProcess = {}



ARGP = argparse.ArgumentParser(
    usage='OKTA_AppSignOnFromCSV_v1.py [-h] [--command "checkPolicy" or "backUpAndDelete" or "applyPolicy" or "enableFedBrokerMode" or "disableFedBrokerMode"] \n \
            [--ruleName "Enter Name of the rule to be created"] \n \
            [--groups "Enter Name groupsIds seperated by colon"] \n \
            [--includedNetworkZoneIds "enter in networkzone Ids seperated by colon"] \n \
            [--excludedNetworkZoneIds "enter out of networkzone Ids seperated by colon"] \n \
            [--action "DENY,ALLOW"] \n \
            [--mfa "ZERO,SESSION,ONE_DAY,ONE_WEEK,ONE_MONTH,SIX_MONTHS,FOREVER"]',

    description=__doc__,
    formatter_class=argparse.RawTextHelpFormatter,
)

ARGP.add_argument('--command', action='store', help='checkPolicy, backUpAndDelete, applyPolicy,  enableFedBrokerMode, disableFedBrokerMode ')
ARGP.add_argument('--includedNetworkZoneIds', action='store', help='enter in networkzone Ids seperated by colon')
ARGP.add_argument('--excludedNetworkZoneIds', action='store', help='enter out of networkzone Ids seperated by colon')
ARGP.add_argument('--mfa', action='store', help='ZERO,SESSION,ONE_DAY,ONE_WEEK,ONE_MONTH,SIX_MONTHS,FOREVER')
ARGP.add_argument('--ruleName', action='store', help='Enter Name of the rule to be created' )
ARGP.add_argument('--groups', action='store', help='Enter Name groupsIds seperated by colon' )
ARGP.add_argument('--action', action='store', help='DENY,ALLOW')

logging.basicConfig(filename='OKTA_AppSignOnFromCSV_v1.log', level=logging.DEBUG)



def main(argp=None):

    availableCommands = ["checkPolicy", "backUpAndDelete", "applyPolicy", "enableFedBrokerMode", "disableFedBrokerMode"]
    if argp is None:
        argp = ARGP.parse_args()  # pragma: no cover

    if 'soemthing_went_wrong' and not argp.command:
        ARGP.print_help()
        ARGP.exit(status=64, message="\nSomething went wrong, --command condition was not set\n")

    if argp.command in availableCommands:
        logging.debug('executing command')
    else:
        ARGP.exit(status=64, message='\nInvalid value for command. Please enter either "checkPolicy", "backUpAndDelete", "applyPolicy", or "enableFedBrokerMode"\n')

    config = loadProperties()

    logging.debug("inside main")
    result,appList = readCsv(config['inputCsv'])


    logging.debug(config['userName'])
    pswd= getpass.getpass('Password:')


    #Create the session
    S=requests.Session()
    
    baseUrl1= 'https://'+config['subDomain']+'.'+config['baseUrl']
    adminBaseUrl= 'https://'+config['subDomain']+'-admin.'+config['baseUrl']
   
    #Grab the adminXsrfToken
    adminXsrfToken = xsrf(S,baseUrl1,adminBaseUrl,config['userName'],pswd)
   
    logging.debug(adminXsrfToken)
    

    for appId,appName in appList.items():
        logging.debug(appId)
        if argp.command == "checkPolicy":
            policyExists = checkForExistingPolicy(S,adminBaseUrl,adminXsrfToken,appId,appName,config['appSignonBackupDirectory'])
            if policyExists:
                logging.error('Custom Policy Exists for the App: %s ---- %s', appName , appId)
            else:
                logging.info('No Custom Policy exits for the App: %s ---- %s', appName , appId)
        elif argp.command == "backUpAndDelete":
            policyExists = backUpAndDeletePolicy(S,adminBaseUrl,adminXsrfToken,appId,appName,config['appSignonBackupDirectory'])
            if policyExists:
                logging.error('Custom Policy Exists for the App: %s ---- %s', appName , appId)
            else:
                allGroupIds = ",".join(result[appId])
                policyName = ",".join(appName)+'_Policy'
                logging.debug(policyName)
                print(Create_App_SignOnPolicy(S,adminBaseUrl,adminXsrfToken,appId,policyName, allGroupIds))
                logging.info('policy applied: %s ---- %s', appName , appId)
        elif argp.command == "applyPolicy":
            # policyExists = checkForExistingPolicy(S,adminBaseUrl,adminXsrfToken,appId,appName,config['appSignonBackupDirectory'])
            # if policyExists:
            #     logging.error('Custom Policy Exists for the App: %s ---- %s', appName , appId)
            #     logging.debug(policyName)
                if argp.groups is not None:
                    groups = argp.groups.replace(':',",")
                else:
                    groups = ",".join(result[appId])
                if argp.includedNetworkZoneIds is None:
                    includedNetworkZoneIds = ''
                else:
                    includedNetworkZoneIds = argp.includedNetworkZoneIds.replace(":",",")
                if argp.excludedNetworkZoneIds is None:
                    excludedNetworkZoneIds = ''
                else:
                    excludedNetworkZoneIds = argp.excludedNetworkZoneIds.replace(":",",")

                if argp.mfa is not None:
                    mfa = argp.mfa
                else:
                    mfa=''
                print(Create_App_SignOnPolicy(S,adminBaseUrl,adminXsrfToken,appId,argp.ruleName,groups,includedNetworkZoneIds,excludedNetworkZoneIds, argp.action,mfa))
                logging.info('policy applied: %s ---- %s', appName , appId)
        elif argp.command == "enableFedBrokerMode":
            print("fedBrokerMode")
            ModifyFedBrokerMode(S,adminBaseUrl,adminXsrfToken,appId,"enabled")
        elif argp.command == "disableFedBrokerMode":
            print("fedBrokerMode")
            ModifyFedBrokerMode(S,adminBaseUrl,adminXsrfToken,appId,"disabled")
        else:
            sys.exit("Invalid Command")
#Get XSRF token
def xsrf(S,baseUrl,adminBaseUrl,username,password):
    #Call the authn api
    body = {'username': username, 'password':password}
    auth = S.post(baseUrl+'/api/v1/authn', json=body)
    json_response=auth.json()
    sessionToken = json_response['sessionToken']

    #Call the api with sessionToken
    response=S.post(baseUrl+'/login/sessionCookieRedirect?token='+sessionToken+'&redirectUrl=/')

    #Get admin login token
    response=S.get(baseUrl+'/home/admin-entry')
    match = re.search(r'"token":\["(.*)"\]', response.text)
    if match:
        # old stlye
        body = {'token': match.group(1)}
        response = S.post(f'{okta_admin_url}/admin/sso/request', data=body)
    # new style (w/ ENG_OIDC_ADMIN_APP_FLOW)
    match = re.search(r'<span.* id="_xsrfToken">(.*)</span>', response.text)
    if not match:
        logging.error('admin_sign_in: token not found. Go to Security > General and disable Multifactor for Administrators.')
        exit()
    Token = match.group(1)

    #Use token to sign in to Okta Admin app, and get admin xsrfToken
    body = {'token': Token}
    header = {"Content-Type" : "application/x-www-form-urlencoded"}
    response=S.post(adminBaseUrl+'/admin/sso/request',data=body,headers=header)
    soup = BeautifulSoup(response.text,'html.parser')
    adminXsrfToken=soup.find(id='_xsrfToken').text
    return adminXsrfToken

#Get OrgId
def orgId(S,baseUrl):
    response=S.get(baseUrl+'/.well-known/okta-organization')
    orgId = response.json()
    return orgId['id']
 


def readCsv(inputMasterCsv):
    logging.debug('inside read csv method')
    with open(inputMasterCsv, mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        line_count = 0
        for row in csv_reader:
            if line_count == 0:
                logging.info(f'Column names are {", ".join(row)}')
            #     line_count += 1
            if row["appId"] in result:
                result[row["appId"]].append(row["groupId"])
            else:
                result[row["appId"]] = [row["groupId"]]
                result[row["networkZones"]] = [row["networkZones"]]
                # jsonObjToProcess[]
                appList[row["appId"]] = [row["appName"]]

            line_count += 1

        logging.debug(json.dumps(result))
        logging.debug(appList)

        logging.debug(f'Processed {line_count} lines.')

    return(result,appList)



def loadProperties():
    # try:
        with open('config.json', mode='r') as json_file:
            config = json.load(json_file)
        return config




       
def checkForExistingPolicy(S,adminBaseUrl,adminXsrfToken,applicationId,applicationName,appSignonBackupDirectory):  

    appType = getAppType(S,adminBaseUrl,applicationId)

    response=S.get(adminBaseUrl+"/admin/app/instance/"+applicationId+"/app-sign-on-policy-list")

    soup = BeautifulSoup(response.text, 'html.parser')

    scriptTag = soup.script.decompose()

    # print(soup)

    data = []

    table_body = soup.find('tbody')

    rows = table_body.find_all('tr', { "class" : "appSignOnRule" })
    for row in rows:
        cols = row.find_all('td')
        cols = [ele.text.strip() for ele in cols]
        # data.append([ele for ele in cols if ele]) # Get rid of empty values
        cols.append(row.get('id').replace('rule-',''))
        data.append(cols)


    rows = table_body.find_all('tr', { "class" : "policy-rule-summary" })
    i=0
    for row in rows:
        cols = row.find_all('p')
        cols = [data[i].append(re.sub(" +","",ele.text.strip())) for ele in cols]
        i+=1

    if not os.path.exists(appSignonBackupDirectory):
        os.makedirs(appSignonBackupDirectory)
    fileToWrite = appSignonBackupDirectory+applicationName[0]+'-'+applicationId+'-Rules.csv'
    with open(fileToWrite, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Priority", "RuleName", "RuleStatus","isEditable","RuleId","Groups","Network","Platforms","Action"])
        for rule in data:
            if rule[6] != "Anywhere":
                ruleres = S.get(adminBaseUrl+"/admin/policy/app-sign-on-rule/"+rule[4])
                rulesoup = BeautifulSoup(ruleres.text, 'html.parser')
                if rule[6] == "Inzone":
                    rule[6] = rule[6].strip() + ':' + rulesoup.find('input', { "id" : "appsignonrule.includedZoneIdString" }).get('value').replace(',',':')
                elif rule[6] == "Notinzone":
                    rule[6] = rule[6].strip() + ':' + rulesoup.find('input', { "name" : "excludedZoneIdString" }).get('value').replace(',',':')
            writer.writerow([rule[0], rule[1], rule[2],rule[3],rule[4],rule[5].replace('\n',''),rule[6],rule[7].replace(',',':'),rule[8].replace('\n',':')])
   
    # table_data = [[cell.text.strip('\n').lstrip().rstrip() for cell in row("td")]
    #                      for row in soup("tr")]



    # print(table_data)
    # print(json.dumps(OrderedDict(table_data)))

    tag1 = 'span class="priority-number"'
    tag = "span"

    reg_str = "<" + tag1 + ">(.*?)</" + tag + ">"


    match = re.findall(reg_str, response.text)


    tag2 = '<tr class="appSignOnRule policy-rule " id="rule-">'

    match2 = re.findall(tag2, response.text )

    if len(match2) == 0 and len(match) == 0 :
        return False
    elif len(match2) == 1 and len(match) == 1:
        return False
    else:
        return True

def backUpAndDeletePolicy(S,adminBaseUrl,adminXsrfToken,applicationId,applicationName,appSignonBackupDirectory):  

    appType = getAppType(S,adminBaseUrl,applicationId)

    response=S.get(adminBaseUrl+"/admin/app/instance/"+applicationId+"/app-sign-on-policy-list")

    soup = BeautifulSoup(response.text, 'html.parser')

    scriptTag = soup.script.decompose()

    # print(soup)

    data = []

    table_body = soup.find('tbody')

    rows = table_body.find_all('tr', { "class" : "appSignOnRule" })
    for row in rows:
        cols = row.find_all('td')
        cols = [ele.text.strip() for ele in cols]
        # data.append([ele for ele in cols if ele]) # Get rid of empty values
        cols.append(row.get('id').replace('rule-',''))
        data.append(cols)


    rows = table_body.find_all('tr', { "class" : "policy-rule-summary" })
    i=0
    for row in rows:
        cols = row.find_all('p')
        cols = [data[i].append(re.sub(" +","",ele.text.strip())) for ele in cols]
        i+=1

    if not os.path.exists(appSignonBackupDirectory):
        os.makedirs(appSignonBackupDirectory)
    fileToWrite = appSignonBackupDirectory+applicationName[0]+'-'+applicationId+'-Rules.csv'
    with open(fileToWrite, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Priority", "RuleName", "RuleStatus","isEditable","RuleId","Groups","Network","Platforms","Action"])
        for rule in data:
            if rule[6] != "Anywhere":
                ruleres = S.get(adminBaseUrl+"/admin/policy/app-sign-on-rule/"+rule[4])
                rulesoup = BeautifulSoup(ruleres.text, 'html.parser')
                if rule[6] == "Inzone":
                    rule[6] = rule[6].strip() + ':' + rulesoup.find('input', { "id" : "appsignonrule.includedZoneIdString" }).get('value').replace(',',':')
                elif rule[6] == "Notinzone":
                    rule[6] = rule[6].strip() + ':' + rulesoup.find('input', { "name" : "excludedZoneIdString" }).get('value').replace(',',':')
            writer.writerow([rule[0], rule[1], rule[2],rule[3],rule[4],rule[5].replace('\n',''),rule[6],rule[7].replace(',',':'),rule[8].replace('\n',':')])
            if rule[3] != "Not editable":
                ruleBody={'_xsrfToken':adminXsrfToken,
                'ruleId':rule[4]
                    }
                delRuleResponse=S.post(adminBaseUrl+"/admin/policy/delete", data=ruleBody)
                logging.debug("Deleted the Rule %s for application %s with status code %s",rule[1], applicationName, delRuleResponse.status_code)
    # table_data = [[cell.text.strip('\n').lstrip().rstrip() for cell in row("td")]
    #                      for row in soup("tr")]



    # print(table_data)
    # print(json.dumps(OrderedDict(table_data)))

    tag1 = 'span class="priority-number"'
    tag = "span"

    reg_str = "<" + tag1 + ">(.*?)</" + tag + ">"


    match = re.findall(reg_str, response.text)


    tag2 = '<tr class="appSignOnRule policy-rule " id="rule-">'

    match2 = re.findall(tag2, response.text )

    if len(match2) == 0 and len(match) == 0 :
        return False
    elif len(match2) == 1 and len(match) == 1:
        return False
    else:
        return True


def Create_App_SignOnPolicy(S,adminBaseUrl,adminXsrfToken,appId,policyName,groups,includedZoneIds, excludedZoneIds, action, mfa): 
    print(includedZoneIds)        
    print(excludedZoneIds)    
    body ='' 
    requireFactor = False
    if mfa != '':
        requireFactor = True

    if includedZoneIds=='' and excludedZoneIds == '':
        body={'_xsrfToken':adminXsrfToken,
        'appInstanceId': appId,
        'name': policyName,
        '_disabled': 'on',
        'hasIncluded': True,
        'location': 'ANYWHERE',
        'includedGroupIdString': groups,
        '_hasIncluded': 'on',
        'action': action,
        'requireFactor': requireFactor,
        'factorLifetime': mfa
        }
    else:      # Method to Enable Integration
        body={'_xsrfToken':adminXsrfToken,
        'appInstanceId': appId,
        'name': policyName,
        '_disabled': 'on',
        'hasIncluded': True,
        'location': 'ZONE',
        'includedZoneIdString': includedZoneIds ,
        'excludedZoneIdString': excludedZoneIds,
        'includedGroupIdString': groups,
        '_hasIncluded': 'on',
        # 'location': 'ANYWHERE',
        'action': action,
        'requireFactor': requireFactor,
        'factorLifetime': mfa
        }

    print(body)
    response=S.post(adminBaseUrl+"/admin/policy/app-sign-on-rule", data=body)
    return(response.status_code)  

def ModifyFedBrokerMode(S,adminBaseUrl,adminXsrfToken,appId,status):                       # Method to Enable Integration
    response=S.get(adminBaseUrl+"/api/v1/apps/"+appId)

    appGetBody = json.loads(response.text)

    appGetBody['settings']['implicitAssignment'] = (True) if (status=="enabled") else (False)

    del appGetBody['lastUpdated']
    del appGetBody['created']

    logging.debug(appGetBody)

    headers = {"Content-Type":"application/json", "x-okta-xsrftoken": adminXsrfToken }

    response1=S.put(adminBaseUrl+"/api/v1/apps/"+appId, data=json.dumps(appGetBody), headers=headers)


    logging.debug(response1.request.headers)


    logging.debug(response1.headers)

    logging.debug(response1.content)

    if response1.status_code == 403:
        logging.error("Federation Broker Mode is not allowed for the app -- %s --- %s", appGetBody['id'], appGetBody['label'])
    else:
        logging.info("Federation Broker Mode is %s for the app -- %s --- %s", status, appGetBody['id'], appGetBody['label'])


def getAppType(S,adminBaseUrl,appId):                       # Method to Enable Integration
    response=S.get(adminBaseUrl+"/api/v1/apps/"+appId)

    appGetBody = json.loads(response.text)

    return appGetBody['name']


def html2json(html: str, debug: bool = False):
    """
   Converts html to a json str.
   """
    collections = {'collections': []}
    result = collections['collections']
    # result has the same reference of the list object
    # inside the list
    fields = 'size identity state name nick'.split()
    skip_fields = 'state nick'.split()
    bs = BeautifulSoup(html, features='html.parser')
    for tr in bs.find_all('tr'):
        state = deque()
        for th_td in tr.children:
            if hasattr(th_td, 'text'):
                state.append(th_td.text)
        if not state:
            continue
        if debug:
            print(state, file=sys.stderr)
        size, identity = state.popleft().strip().split()
        size = int(size)
        state.extendleft((size, identity))
        dataset = {
            field: value for (field, value) in
            zip(fields, state)
            if field not in skip_fields
        }
        result.append(dataset)
    return json.dumps(collections, indent=4)

if __name__== "__main__":
        main()
