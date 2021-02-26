from colorama import init
from colorama import Fore
init()
print(Fore.GREEN + "Vulnerability Report Summary")

import xlsxwriter
import openpyxl
import itertools
import threading
import time
import sys
import daemon
import pandas as pd
import tkinter as tk
from tkinter import filedialog
import re
import collections


#Quick method of counting the number of vulns in each CVSSv3 risk category(None,Low,etc.)
def cvsscount():

#Opens file window to select .xlsx file
    print('\n'+ 'Please select your formatted report in .xlsx format' + Fore.RESET)
    root = tk.Tk()
    root.withdraw()
    filepath = filedialog.askopenfilename()
    print(Fore.YELLOW + filepath + Fore.RESET)


    #Sets parameters for animation
    done = False
    def count():
        for c in itertools.cycle(['|','/','-', '\\']):
            if done:
                print('\n')
                break
            sys.stdout.write('\rCounting...' + c)
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('Summary below!')
    a = threading.Thread(target=count)
    a.daemon=True
    a.start()

#Declares IP address pattern for matching, sets counters, opens Excel document and counts number of each CVSSv3 Score
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    count30Day = 0
    countIP = 0
    count7zip = 0
    countAdobe = 0
    countApache = 0
    countArtifex = 0
    countAtlassian = 0
    countCIFS = 0
    countDefender = 0
    countFirefox = 0
    countGoogle = 0
    countIBM = 0
    countJava = 0
    countMicrosoft = 0
    countMongo = 0
    countOffice = 0
    countPHP = 0
    countRedHat = 0
    countSSH = 0
    countSolaris = 0
    countSymantec = 0
    countTLS = 0
    countWinRAR = 0
    countWireshark = 0
    countVMWare = 0

#Creates data frames to gather values for summarizing
    dfscore = pd.read_excel(filepath, 'Report'.capitalize())['Vulnerability CVSSv3 Score']

    dfdays = pd.read_excel(filepath, 'Report'.capitalize())['Vulnerability Age']
    dfdays = dfdays.replace({'Days':''}, regex=True)
    dfdays = dfdays.replace({'Day':''}, regex=True)

    dfboth = pd.concat([dfdays,dfscore], axis=1,sort = False)
    dfboth['Vulnerability Age'] = dfboth['Vulnerability Age'].astype(str).astype(int)
    dfboth['Vulnerability CVSSv3 Score'] = dfboth['Vulnerability CVSSv3 Score'].astype(str).astype(float)

    iplst = pd.read_excel(filepath, 'Report'.capitalize())['Asset IP Address'].tolist()
    iplst = list(dict.fromkeys(iplst))
    for line in iplst:
        line = line.strip()
        match = pattern.search(line)
        if match:
            countIP += 1

    cvss = dfscore.value_counts().sort_index()
    days = dfdays.value_counts().sort_index()

    hc30 = (dfboth['Vulnerability Age'] > 30) & (dfboth['Vulnerability CVSSv3 Score'] > 6.9)
    for rows in hc30:
         if rows == True:
             count30Day = count30Day + 1
#Counts number of each vulnerability for top 4 category

    dftitle = pd.read_excel(filepath, 'Report'.capitalize())['Vulnerability Title']
    titlelst = dftitle.tolist()
    countlst = []
    for line in titlelst:
        line = line.strip()
        if line.find('7-Zip') != -1:
            count7zip += 1
            countlst.append('7-Zip')
        if line.find('Adobe') != -1:
            countAdobe += 1
            countlst.append('Adobe')
        if line.find('Apache') != -1:
            countApache += 1
            countlst.append('Apache')
        if line.find('Artifex') != -1:
            countArtifex += 1
            countlst.append('Artifex')
        if line.find('Atlassian') != -1:
            countAtlassian += 1
            countlst.append('Atlassian')
        if line.find('CIFS') != -1:
            countCIFS += 1
            countlst.append('CIFS')
        if line.find('Defender') != -1:
            countDefender += 1
            countlst.append('Defender')
        if line.find('Firefox') != -1:
            countFirefox += 1
            countlst.append('Firefox')
        if line.find('Google') != -1:
            countGoogle += 1
            countlst.append('Google')
        if line.find('IBM') != -1:
            countIBM += 1
            countlst.append('IBM')
        if line.find('Java') != -1:
            countJava += 1
            countlst.append('Java')
        if line.find('Microsoft') != -1:
            countMicrosoft += 1
        if line.find('Mongo') != -1:
            countMongo += 1
        if line.find('Office') != -1:
            countOffice += 1
        if line.find('PHP') != -1:
            countPHP += 1
            countlst.append('PHP')
        if line.find('Red Hat') != -1:
            countRedHat += 1
            countlst.append('Red Hat')
        if line.find('SSH') != -1:
            countSSH += 1
            countlst.append('SSH')
        if line.find('Solaris') != -1:
            countSolaris += 1
            countlst.append('Solaris')
        if line.find('Symantec') != -1:
            countSymantec += 1
            countlst.append('Symantec')
        if line.find('TLS') != -1:
            countTLS += 1
            countlst.append('TLS')
        if line.find('WinRAR') != -1:
            countWinRAR += 1
            countlst.append('WinRAR')
        if line.find('Wireshark') != -1:
            countWireshark += 1
            countlst.append('Wireshark')
        if line.find('VMWare') != -1:
            countVMWare += 1
            countlst.append('VMWare')

    done = True
    time.sleep(0.5)
    stop_threads = True

    counts = {'7-Zip:': count7zip, 'Adobe:': countAdobe, 'Apache:': countApache, 'Artifex:': countArtifex, 'Atlassian:': countAtlassian, 'CIFS:': countCIFS, 'Defender:': countDefender,
    'Firefox:': countFirefox, 'Google:': countGoogle, 'IBM:':countIBM, 'PHP:': countPHP, 'SSH:': countSSH, 'Solaris: ': countSolaris, 'Symantec:':countSymantec, 'TLS:':countTLS, 'WinRAR:':countWinRAR,
    'Wireshark:':countWireshark, 'VMWare:':countVMWare, 'Java:':countJava, 'Microsoft:':countMicrosoft,'Red Hat:':countRedHat, 'Mongo:':countMongo, 'Office:':countOffice}
    sort_counts = sorted(counts.items(), key=lambda x: x[1], reverse = True)
#Outputs data into CLI for copying onto summary page
    print('\n' + '\n' + 'Asset Count:',countIP)
    print('\n' + 'CVSSv3 Scores')
    print("\rNone (0):",cvss.loc[0.0])
    print("\rLow (0.1 - 3.9):",cvss.loc[0.1:3.9].sum())
    print("\rMedium (4.0 - 6.9):",cvss.loc[4.0:6.9].sum())
    print(Fore.RED + "\rHigh (7.0 - 8.9):",cvss.loc[7.0:8.9].sum())
    print("\rCritical (9.0 - 10.0):",cvss.loc[9.0:10.0].sum())

    print('\n'+"\rHigh & Critical >30 Days:",count30Day)
    print(Fore.RESET +"\rTotal Vulns:",cvss.loc[0.0:10.0].sum())

    print('\n' + "\rTop 4 Vulnerabilities")
    #for i in sort_counts[0:4]:
        print(i[0], i[1])


    #workbook = load_workbook(filepath)
    #worksheet = workbook['summary'.capitalize()]
    #print(dflow)

try:

    cvsscount()

    done = True
    time.sleep(0.5)
    sys.stdout.write(Fore.GREEN + '\n'  + 'Done!' + '\n' + Fore.RESET)

except:
    print("An unexpected error occured, please try again!")
