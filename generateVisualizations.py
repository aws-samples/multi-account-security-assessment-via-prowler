'''
Authors: Cameron Covington and Mike Virgilio
Purpose: Prowler V3 report processing
Input: Aggregated results CSV with access denied failures removed
Output: Generate graphs to visualize the Prowler results
'''
import csv
import os
import sys

from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np

# Get command line arguments, if any
print("Processing with ", len(sys.argv), "argument(s)")

# Counters for pass/fail/info
failCount=0
passCount=0
infoCount=0
totalCount=0

# Counter for each severity failures
lowFailures=0
mediumFailures=0
highFailures=0
criticalFailures=0

# Counter for each severity passes
lowPasses=0
mediumPasses=0
highPasses=0
criticalPasses=0

# Overall counters to check for completeness
counter=0
rowCount=0
servicesPassFail={}
accountIdResult={}

# Output directory for saved figures
savePath='/usr/local/prowler/output/ResultsVisualizations-'+str(datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
os.mkdir(savePath)

# Process command line arguments, allowing the user to specify a result file name to process
# If none is given, use the default prowler-fullorgresults-accessdeniedfiltered.txt
if len(sys.argv)==2:
    resultFile=str(sys.argv[1])
else:
    resultFile='/usr/local/prowler/output/prowler-fullorgresults-accessdeniedfiltered.txt'

print("Processing file: ", resultFile)

with open(resultFile, newline='') as csvfile:
    csvProcessor = csv.DictReader(csvfile, delimiter=';')
    for row in csvProcessor:
        # Process pass/fail results
        passFail=row['STATUS']
        severity=row['SEVERITY']
        service=row['SERVICE_NAME']
        accountId=row['ACCOUNT_ID']
        
        # Create a dictionary of pass/fail by service and keep a count for each
        try:
            if service!="SERVICE_NAME" and passFail=="FAIL":
                cnt=servicesPassFail[service]
                cnt+=1
                servicesPassFail[service]=cnt
        except:
            servicesPassFail[service]=1

        try:
            if accountId!="ACCOUNT_ID" and passFail=="FAIL":
                cnt=accountIdResult[accountId]
                cnt+=1
                accountIdResult[accountId]=cnt
        except:
            accountIdResult[accountId]=1

        rowCount+=1
        if (passFail=="FAIL" and severity=="low"):
            failCount+=1
            lowFailures+=1
        if (passFail=="FAIL" and severity=="medium"):
            failCount+=1
            mediumFailures+=1
        if (passFail=="FAIL" and severity=="high"):
            failCount+=1
            highFailures+=1
        if (passFail=="FAIL" and severity=="critical"):
            failCount+=1
            criticalFailures+=1
        if (passFail=="PASS" and severity=="low"):
            passCount+=1
            lowPasses+=1
        if (passFail=="PASS" and severity=="medium"):
            passCount+=1
            mediumPasses+=1
        if (passFail=="PASS" and severity=="high"):
            passCount+=1
            highPasses+=1
        if (passFail=="PASS" and severity=="critical"):
            passCount+=1
            criticalPasses+=1
        if (passFail=="INFO"):
            infoCount+=1

# Print basic information about the scan result
print("Failures by service:")   
for key, value in servicesPassFail.items():
    key=str(key)
    print('{:15s}'.format(key), value)
print("="*60)

print("Failures by account ID:")
for key, value in accountIdResult.items():
    key=str(key)
    print('{:20s}'.format(key), value)
print("="*60)
        
# Print counts by severity
print("Fail count:", failCount)
print("Pass count: ", passCount)
print("Info count: ", infoCount)
print("="*60)

# Print failures
print("Low failures:", lowFailures)
print("Medium failures:", mediumFailures)
print("High failures:", highFailures)
print("Critical failures:", criticalFailures)
totalFailures=lowFailures+mediumFailures+highFailures+criticalFailures
print("Total failures: ", totalFailures)
print("="*60)

# Print passes
print("Low passes:", lowPasses)
print("Medium passes:", mediumPasses)
print("High passes:", highPasses)
print("Critical passes:", criticalPasses)
totalPasses=lowPasses+mediumPasses+highPasses+criticalPasses
print("Total passes", totalPasses)
print("="*60)

# Print totals
print("Total rows processed:", rowCount)
print("Failures+Passes+Info:", failCount+passCount+infoCount+1) # Account for the header row
totalCount = failCount+passCount+infoCount

# ===============================
# | Bar chart of failures        |
# ===============================
severity = ['Info', 'Low Failures', 'Medium Failures', 'High Failures', 'Critical Failures']
failures = [infoCount, lowFailures, mediumFailures, highFailures, criticalFailures]

# Format the bar chart and display
fig, ax = plt.subplots(figsize=(10,4))
ax.barh(severity, failures)
for i in range(len(failures)):
    plt.text(failures[i], severity[i], failures[i], va="center")
plt.title('Processed Results by Failure Severity Count')
plt.autoscale(enable=True)
plt.xlabel('count')
plt.ylabel('severity')
now = datetime.now()
currentTime = now.strftime("%H-%M-%S")
failuresBySeverityCount = "ProcessedResultsByFailureSeverityCount-" + str(now.date()) + "-" + currentTime + ".png"
figure = os.path.join(savePath ,failuresBySeverityCount)
plt.savefig(figure)

# ======================================
# | Pie chart of failures by severity   |
# ======================================
pieLabels=['Low', 'Medium', 'High', 'Critical']
y=np.array([lowFailures, mediumFailures, highFailures, criticalFailures])

# Format the legend
legendValues=[(lowFailures/failCount*100), (mediumFailures/failCount*100), (highFailures/failCount*100), (criticalFailures/failCount*100)]
labels = [f'{l}, {s:0.1f}%' for l, s in zip(pieLabels, legendValues)]

# Format the pie chart and display
fig, ax = plt.subplots()
colors=["green", "orange", "red", "purple"]
ax.pie(y,colors=colors, autopct=lambda p: '{:.0f}'.format(p *y.sum() / 100), shadow=False)
plt.legend(bbox_to_anchor=(1, 0.5), loc='best', labels=labels)
plt.title("Results by Failure Severity\n\n")
plt.autoscale(enable=True, tight=True)
now = datetime.now()
currentTime = now.strftime("%H-%M-%S")
resultsByFail = "ResultsByFail-" + str(now.date()) + "-" + currentTime + ".png"
figure = os.path.join(savePath,resultsByFail)
plt.savefig(figure, bbox_inches='tight')

# =================================================
# | Pie chart of passes and failures by severity   |
# =================================================
pieLabels=['Info', 'Low-Failed', 'Medium-Failed', 'High-Failed', 'Critical-Failed', 'Low-Passed', 'Medium-Passed', 'High-Passed', 'Critical-Passed']
y=np.array([infoCount, lowFailures, mediumFailures, highFailures, criticalFailures, lowPasses, mediumPasses, highPasses, criticalPasses])

# Format the legend
legendValues=[(infoCount/totalCount*100), (lowFailures/totalCount*100), (mediumFailures/totalCount*100), (highFailures/totalCount*100), (criticalFailures/totalCount*100),
    (lowPasses/totalCount*100), (mediumPasses/totalCount*100), (highPasses/totalCount*100), (criticalPasses/totalCount*100)]
labels = [f'{l}, {s:0.1f}%' for l, s in zip(pieLabels, legendValues)]

# Format the pie chart and display
fig, ax = plt.subplots()
colors=["blue", "green", "orange", "red", "purple", "yellow", "brown", "magenta"]
ax.pie(y, labels=pieLabels, colors=colors,
   autopct=lambda p: '{:.0f}'.format(p *y.sum() / 100),
   shadow=False)

plt.legend(loc='best', labels=labels, fontsize="xx-small", bbox_to_anchor=(1, 0.5))
plt.title("Results by severity\n\n")
plt.autoscale(enable=True, tight=True)
now = datetime.now()
currentTime = now.strftime("%H-%M-%S")
resultsBySeverity = "ResultsbySeverity-" + str(now.date()) + "-" + currentTime + ".png"
figure = os.path.join(savePath, resultsBySeverity)
plt.savefig(figure, bbox_inches='tight', dpi=600)

# ========================================
# | Bar chart of failures by service      |
# ========================================
services=list(servicesPassFail.keys())
failures=list(servicesPassFail.values())

# Format the bar chart and display
fig, ax = plt.subplots(figsize=(10,10))
ax.barh(services, failures)
ax.autoscale(enable=True)
plt.autoscale(enable=True)
ax.set_xticklabels(failures)
for i in range(len(failures)):
    plt.text(failures[i], services[i], failures[i], va="center")
plt.title("Failures by service")
plt.xlabel('Failure count')
now = datetime.now()
plt.tight_layout()
currentTime = now.strftime("%H-%M-%S")
failuresByService = "FailuresByService-" + str(now.date()) + "-" + currentTime + ".png"
figure = os.path.join(savePath, failuresByService)
plt.savefig(figure)

# ========================================
# | Bar chart of failures by account ID   |
# ========================================
accounts=list(accountIdResult.keys())
failures=list(accountIdResult.values())

# Format the bar chart and display
fig, ax = plt.subplots(figsize=(len(accounts), len(failures)))
ax.barh(accounts, failures)
ax.autoscale(enable=True)
plt.title("Failures by account ID")
plt.xlabel('Failure count')
plt.tight_layout()
for i in range(len(failures)):
    plt.text(failures[i], accounts[i], failures[i], va="center")
now = datetime.now()
currentTime = now.strftime("%H-%M-%S")
failuresByAccount = "FailuresByAccount-" + str(now.date()) + "-" + currentTime + ".png"
figure = os.path.join(savePath, failuresByAccount)
plt.savefig(figure)

# ========================================
# | HTML file with each graph generated   |
# ========================================
htmlFile = open(os.path.join(savePath, 'ProwlerReport.html'), 'w')
date = datetime.now()
htmlTemplate = f"""<html>
<head>
<title>Prowler Repoort</title>
</head>
<body>
<h1>Prowler Report</h1>
<p>{date}</p>

<h3>Failures by Severity</h3>
<img src="./{failuresBySeverityCount}" width="900"></img>
<br>
<h2>Failures by Result</h2>
<img src="./{resultsByFail}" width="900"></img>
<br>
<h3>Pass/Fail by Severity</h3>
<img src="./{resultsBySeverity}" width="900"></img>
<br>
<h3>Failures by Service</h3>
<img src="./{failuresByService}" width="900"></img>
<br>
<h3>Failures by Account</h3>
<img src="./{failuresByAccount}" width="900"></img>
<br>
<h2>Failures by Severity</h2>
Low failures: {lowFailures}<br>
Medium failures: {mediumFailures}<br>
High failures: {highFailures}<br>
Critical failures: {criticalFailures}<br>
Total failures: {totalFailures}<br>
<br>
<br>
<h2>Passes by Severity</h2>
Low passes: {lowPasses}<br>
Medium passes: {mediumPasses}<br>
High passes: {highPasses}<br>
Critical passes: {criticalPasses}<br>
Total passes: {totalPasses}
</p>
</body>
</html>
"""
htmlFile.write(htmlTemplate)
