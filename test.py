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
mystr = ''
for k in ans1:
    print(k.split('='))
    temp1 = k.split('=')
    if len(temp1)>2:
        i = 1
        for j in temp1:
            if i<len(temp1):
                mystr = mystr+temp1[i]
                i+=1
        print(mystr)
 #   keylist.append(temp1[0])




#print(keylist)
#re.findall(['=']{1})







sys.exit(0)
#res = re.split(', |_|-|!', data)
res = re.split("[\n |]+", data)
print(res)
res.remove("SAC:0",'Sacumen')
print(res)
#data = {k.split('=')[0].strip():k.split('=')[1].strip() for k in res}
#print(data)








sys.exit(0)


def sampleinput(data:str):
    data = [k for k in data.split('\n') if len(k)>3]
    print(data)
    print('-------------------------------------------------------------')
    data = {k.split('=')[0].strip():k.split('=')[1].strip() for k in data}
    print('-------------------------------------------------------------')
    for key,value in data.items():
        print(key,":",value)

sampleinput(data)













sys.exit(0)