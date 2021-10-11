import sys
import re

data ='''SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1'''

def convstr_to_dict(strings:str):
    data = [k for k in strings.split('|')]
    output_data = data[7]
    #print(output_data)
    leftsplt = output_data.split(' ',11)
    l2 = leftsplt[-1].rsplit(' ',2)
    l1 = leftsplt[0:-1]
    #print(l1)
    #print(l2)
    l3 = l1+l2
    #print(l3)
    keylst = []
    valuelst = []
    for x in l3:
        l4 = x.split('=',1)
        keylst.append(l4[0])
        valuelst.append(l4[1])

    finalans = dict(zip(keylst, valuelst))
    return finalans

print(convstr_to_dict(data))
print(type(convstr_to_dict(data)))









sys.exit(0)






