import msal
import requests
import json
import svc_config


# send to splunk
def send_to_splunk(d):
    requests.post(url=svc_config.splunk_URL, headers={'Authorization': svc_config.splunk_Auth}, data=d, verify=True)
        
# Lets get that Token boys
def get_access_token():
    scope = ['https://graph.microsoft.com/.default']
    app = msal.ConfidentialClientApplication(svc_config.Az_config['client_id'], authority=svc_config.Az_config['authority'], client_credential=svc_config.Az_config['client_secret'])
    access_token = app.acquire_token_for_client(scopes=scope)
    return access_token

def SimDataCoverage(azheader, url='https://graph.microsoft.com/v1.0/reports/security/getAttackSimulationSimulationUserCoverage'):
    jsonData = requests.get(url, headers=azheader)
    parsed_data = json.loads(jsonData.text)

    # Accessing specific values
    context = parsed_data['@odata.context']
    next_link = parsed_data['@odata.nextLink']
    simulation_users = parsed_data['value']

    # Accessing information about simulation users
    for user in simulation_users:
        #print("\nUser:")
        #print("User ID:", user['attackSimulationUser']['userId'])
        #print("Display Name:", user['attackSimulationUser']['displayName'])
        #print("Email:", user['attackSimulationUser']['email'])
        #print("Simulation Count:", user['simulationCount'])
        #print("Latest Simulation DateTime:", user['latestSimulationDateTime'])
        #print("Click Count:", user['clickCount'])
        #print("Compromised Count:", user['compromisedCount'])
        sdata = '{"sourcetype": "AttackSimulations","source": "AttackSimulationSimulationUserCoverage","host":"MSGraphAPIPython","event":"'
        sdata += 'compromisedCount='+str(user['compromisedCount'])+','
        sdata += 'clickCount='+str(user['clickCount'])+','
        sdata += 'latestSimulationDateTime='+str(user['latestSimulationDateTime'])+','
        sdata += 'simulationCount='+str(user['simulationCount'])+','
        sdata += 'displayName='+str((user['attackSimulationUser']['displayName']).replace(",", ""))+','
        sdata += 'email='+str(user['attackSimulationUser']['email'])+''
        sdata += '"}'
        #send_to_splunk(sdata)
        print (sdata+"\n")

def SimDataTraining(azheader, url='https://graph.microsoft.com/v1.0/reports/security/getAttackSimulationTrainingUserCoverage'):
    jsonData = requests.get(url, headers=azheader)
    data = jsonData.json()
    # Extract information from the parsed JSON
    context = data.get('@odata.context', '')
    next_link = data.get('@odata.nextLink', '')
    users = data.get('value', [])

    # Process the user data
    for user in users:
        user_info = user.get('attackSimulationUser', {})
        display_name = (user_info.get('displayName', '')).replace(",", " ")
        email = (user_info.get('email', ''))

        user_trainings = user.get('userTrainings', [])
        for training in user_trainings:
            assigned_datetime = (training.get('assignedDateTime', ''))
            completion_datetime = (training.get('completionDateTime', ''))
            training_status = (training.get('trainingStatus', '')).replace(",", "")
            training_display_name = (training.get('displayName', '')).replace(",", " ")

            # Print or process the extracted information as needed
            #print(f"User: {display_name} ({email})")
            #print(f"Training: {training_display_name}")
            #print(f"Assigned DateTime: {assigned_datetime}")
            #print(f"Completion DateTime: {completion_datetime}")
            #print(f"Training Status: {training_status}")
            sdata = '{"sourcetype": "AttackSimulations","source": "AttackSimulationTrainingUserCoverage","host":"MSGraphAPIPython","event":"'
            sdata += 'TrainingStatus='+str(training_status)+','
            sdata += 'CompletionDateTime='+str(completion_datetime)+','
            sdata += 'AssignedDateTime='+str(assigned_datetime)+','
            sdata += 'Training='+str(training_display_name)+','
            sdata += 'displayName='+str(display_name)+','
            sdata += 'email='+str(email)+''
            sdata += '"}'
            #send_to_splunk(sdata)
            print (sdata+"\n")

def SimDataRepeatOffenders(azheader, url='https://graph.microsoft.com/v1.0/reports/security/getAttackSimulationRepeatOffenders'):
    jsonData = requests.get(url, headers=azheader)
    ParseData = json.loads(jsonData.text)

    # Accessing values
    for item in ParseData['value']:
        user_data = item['attackSimulationUser']
        #print(f"Repeat Offence Count: {item['repeatOffenceCount']}")
        #print(f"User ID: {user_data['userId']}")
        #print(f"Display Name: {user_data['displayName']}")
        #print(f"Email: {user_data['email']}")

        data = '{"sourcetype": "AttackSimulations","source": "AttackSimulationRepeatOffenders","host":"MSGraphAPIPython","event":"'
        data += 'repeatOffenceCount='+str(item['repeatOffenceCount'])+','
        data += 'displayName='+str(user_data['displayName'])+','
        data += 'email='+str(user_data['email'])+''
        data += '"}'
        #send_to_splunk(data)
        print (data+"\n")

# run main function
def run_main():
    # get token block & Set the headers for the API call
    access_token = get_access_token()
    az_headers = {"Authorization": f"Bearer {access_token['access_token']}", "Content-Type": "application/json"}
    # Lets get top offendors
    #SimDataCoverage(az_headers)

    # Lets get top offendors - done
    SimDataTraining(az_headers)

    # Lets get top offendors - done
    #SimDataRepeatOffenders(az_headers)

run_main()
