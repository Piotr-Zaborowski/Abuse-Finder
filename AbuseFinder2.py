from ipwhois import IPWhois
from pprint import pprint
import socket
import json

def FindByString(resstring):    #Function finding abuse by string of "type": "abuse", "value": "
    str1 = '"';
    str2 = '"type": "abuse", "value": "';
    try:
        abuseplace = resstring.index(str2)+27  # finding abuse email adress
        endabuseplace = resstring.index(str1, abuseplace + 1)  # finding end of abuse email adress
        abusemail = resstring[abuseplace:endabuseplace]  # abuse email adress found
    except ValueError:
        abusemail=FindByMail(resstring)
    return abusemail

def FindByMail(resstring): #Function finds abuse emial adress by searching for abuse@
    str1 = '"';
    str2 = "abuse@";
    abuseplace = resstring.index(str2)  # finding abuse email adress
    endabuseplace = resstring.index(str1, abuseplace + 1)  # finding end of abuse email adress
    abusemail = resstring[abuseplace:endabuseplace]  # abuse email adress found
    return abusemail

def ShortenURL(domainName): #shortening URL for it just to ba a diomain adress
    str1 = 'https://';
    str2 = '/';
    srt3 = 'http://'
    if ('https://' in domainName):
        startplece = domainName.index(str1)+8
    else:
        if ('http://' in domainName):
            startplece = domainName.index(srt3)+7
        else:
            if ('/' in domainName):
                return domainName[0:domainName.index(str2)]
            else:
                return domainName;
    endaplace = domainName.index(str2, startplece+1)
    shortenDomainName = domainName[startplece:endaplace]
    return shortenDomainName

def DecypherURL(domainName): #Function for replacing hxxps:// , hxxp:// , [.]
    toreturndots=domainName.replace('[.]','.')
    if ('hxxps://' in domainName):
        newtoreturndots=domainName.replace("hxxps://","https://")
    else:
        if ('hxxp://' in domainName):
            newtoreturndots=domainName.replace('hxxp://','http://')
        else:
            return toreturndots
    return newtoreturndots

def FindAbuse(NotCheckedURL): #main function, that returns abuse email adress for any giver URL
    finalstring = ''
    NotDecyphered = ShortenURL(NotCheckedURL)
    domainName = DecypherURL(NotDecyphered)
    # print(domainName)
    try:
        ipadresss = (socket.gethostbyname(domainName))  # Getting IP adress for given www
        obj = IPWhois(ipadresss)
        results = obj.lookup_rdap(depth=1)  # getting whois info
        resstring = json.dumps(results)  # getting string from results which is a dict
        # print(resstring)           #used for debugging and showing full whois info
        abusemail = FindByString(resstring)
        finalstring = finalstring + abusemail + ' ' + domainName + ' ' + ipadresss
    except socket.error:
        print(domainName+" ERROR_Incorrect_web_adress_given_ERROR")
    return finalstring



# Using readline()
file1 = open('doobrobki.txt', 'r')
count = 0

while True:
    count += 1
    line = file1.readline()
    if not line:
        break
    NotCheckedURL=line.strip()
    print(FindAbuse(NotCheckedURL))
file1.close()



