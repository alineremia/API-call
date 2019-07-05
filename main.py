import requests
import json
import objectpath
import ast


url = 'https://www.virustotal.com/vtapi/v2/file/report'
params = {'apikey': '<apikey>', 'resource': '<resource>'}
response = requests.get(url, params=params)


if response.status_code == 200:
    print('Success!\n')
    json_response = response.json()
    scans = json_response['scans']

    for product, values in scans.items():
        for key in product:     
            if(values['detected'] == True):
                val = str(values['result'])
                print (str(product) + "  " + val)
                break                   
else :
    print('\nError, check keys!\n')

print("\nEND")
quit()
