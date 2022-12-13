# Multi-Account Security Assessment via Prowler with Batching and Post Processing

# Table of Contents

**1. [Overview](#Overview)**

**2. [Resources](#Resources)**

**3. [Implementation Procedures](#ImplementationProcedures)**

**4. [Appendix](#Appendix)**

# **Overview** <a name="Overview"></a>

Execution of prowler requires deployment of an IAM Role to all accounts being scanned, an IAM Role which the EC2 instance running prowler will utilize, the deployment of an EC2 instance running the prowler software, and an S3 bucket to store the output. This procedure has been validated with prowler versions 2.6-2.12.

# **Resources** <a name="Resources"></a>

prowler\_scan.sh: Bash script used for assessing multiple AWS accounts in parallel. This script is automatically deployed onto the EC2 instance in the folder /usr/local/bin/prowler via the prowler-resources.yaml CFT in userdata. By default, this script assumes the IAM role "ProwlerExecRole" in the management account to generate a list of member accounts in the AWS Org. The script then uses this list of accounts to begin an assessment of the accounts. As the accounts are assessed, they will output results in the prowler/outputs directory in CSV and HTML formats. Once all accounts have been assessed, the individual CSV files will be concatenated, duplicate lines removed, and all output files zipped. Note: This script has tunable variables within the script itself (See appendix for more details). This script is provided independently from the CFT for reference.

Prowler-resources.yaml: A CFN template which is deployed in the account where the prowler EC2 instance will be deployed. This template will deploy all necessary dependencies in order for prowler to perform assessments across all accounts. The IAM-ProwlerExecRole is dependent on this template being deployed first. Note: If this stack is deleted and redeployed, the ProwlerExecRole StackSet will need to be re-deployed to rebuild the cross-account dependency between IAM Roles.

IAM-ProwlerExecRole.yaml: A CFN template to be deployed via StackSet across all member accounts. This will create an IAM Role which can be assumed by prowler during scanning.

prowler-report-template.xlsm: An excel document for processing of findings. Pivot tables allow for search capabilities, charts, and consolidated findings. Note: The excel document version must match with a supported version of prowler.

**External Web URLs:**

Prowler Source: [https://github.com/prowler-cloud/prowler](https://github.com/prowler-cloud/prowler)

CIS Benchmarks: [https://d0.awsstatic.com/whitepapers/compliance/AWS\_CIS\_Foundations\_Benchmark.pdf](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf)


# **Implementation Procedures** <a name="ImplemementationProcedures"></a>

1. Select an account where the Prowler EC2 instance will be provisioned. Log into this account and deploy the Prowler Resources CloudFormation template. (prowler-resources.yaml)  
Note: Use an account such as Security or CommonServices for the Prowler EC2 deploy. When deploying the CFN template, it will provision an IAM Role, S3 Bucket with policy, and EC2 instance which will be used by Prowler.

    a. Deploy the prowler-resources.yaml CFN template.
    1. Open the CloudFormation console
    2. Create Stack -\> With new resources
    3. Prerequisite - Prepare template: "Template is ready"
    4. Specify template: "Upload a template file" -\> "Choose File" -\> Browse for the template
        1. Specify the prowler-resources.yaml template
    5. Next
    6. Specify stack details
        1. StackSet name: Prowler-Resources
        2. Parameters:
            1. VPCId: Select a VPC in the account
            2. SubnetId: Select a private subnet which has Internet access
            3. InstanceType: Select an instance size based on the number of parallel assessments. Guidelines: 4=c6i.large, 6=c6i.xlarge, 8=c6i.2xlarge
            4. InstanceImageId: Leave the default for Amazon Linux 2
            5. EC2InstanceRole: Leave the default unless necessary
            6. KeyPairName: Specify the name of an existing KeyPair if using SSH for access (This is optional and can be left blank)
            7. PermittedSSHInbound: If using SSH for access, specify a permitted CIDR
            8. BucketName: Leave the default unless necessary
            9. EmailAddress: Specify an email address for a SNS notification when Prowler completes the assessment and uploads the zip file to S3.
            >Note: The SNS subscription configuration must be confirmed prior to Prowler completing the assessment or a notification will not be sent.
            10. IAMProwlerEC2Role: Leave the default unless necessary
            11. IAMPRowlerExecRole: Leave the default unless necessary
            12. Parallelism: Specify the number of parallel assessments to perform.
            >Note: Specify the proper InstanceType parameter value
            13. Next
            14. Next
            15. Review
            16. Check the box for "The following resource(s) require capabilities: [AWS::IAM::Role]" and Create Stack
            17. Once the Stack has finished deploying, click the Outputs tab in the CloudFormation console and copy the ProwlerEC2Role ARN for use with the next CloudFormation template deploys.

2. Log into the AWS Org management account (root) in order to deploy a CloudFormation StackSet across the AWS Organization and a Stack to the management account.  
Note: The easiest way to do this is to utilize service-managed permissions when deploying the stack and deploying to the entire organization. This will require trust to be established between CloudFormation and the AWS Organization. If it is not already established, the CloudFormation console for StackSets will present a button which should be clicked and states "Enable trusted access with AWS Organizations to use service-managed permissions." This can be safely enabled (with the appropriate approval) without impacting existing stacks and can also be disabled at a later time via command line.

    a. Deploy the IAM-ProwlerExecRole.yaml CFN template to all accounts in the Organization via a StackSet
    1. Open the CloudFormation console
    2. Click StackSets
    3. Click "Create StackSet"
    4. Prerequisite - Prepare template: "Template is ready"
    5. Specify template: "Upload a template file" -\> "Choose File" -\> Browse for the template.
            1. Specify the IAM-ProwlerExecRole.yaml template.
    6. Next
    7. Specify StackSet details
            1. StackSet name: IAM-ProwlerExecRole
            2. Parameters:
                1. AuthorizedARN: Specify the ProwlerEC2Role ARN which was provisioned as part of the prowler-resources.yaml stack.
                2. ProwlerRoleName: Leave the default (ProwlerExecRole)
    8. Permissions: Service-managed permissions
    9. Deployment targets: Leave "Deploy to organization" selected along with defaults
    10. Specify regions: Select a single region as IAM is global. (E.g., Use the region the Prowler EC2 Instance will be deployed in)
    11. OPTIONAL: Specify Deployment Options: Set BOTH "Maximum concurrent accounts" and "Failure tolerance" to a high number (E.g. 100) to have the stacks deploy to this number of AWS accounts simultaneously.
    12. Next
    13. Review
    14. Check the box to approve "I acknowledge that AWS CloudFormation might create IAM resources with custom names."
    15. Submit\
    Monitor the "Stack instances" (Individual account status) and Operations (Overall) tabs to determine when the deploy is completed. This will take some time to deploy across all accounts.

    b. Deploy the IAM-ProwlerExecRole.yaml CFN template to the AWS Org management account (root) via a stack.\
    Note: This deployment is direct to the management account as the StackSet deployed previously does not include the management account.
    1. Open the CloudFormation console
    2. Create Stack -\> With new resources
    3. Prerequisite - Prepare template: "Template is ready"
    4. Specify template: "Upload a template file" -\> "Choose File" -\> Browse for the template
        1. Specify the IAM-ProwlerExecRole.yaml template
    5. Next
    6. Specify stack details
        1. Stack name: IAM-ProwlerExecRole
        2. Parameters:
            1. AuthorizedARN: Specify the ProwlerEC2Role ARN which was provisioned as part of the Prowler-Resources stack.
            2. ProwlerRoleName: Leave the default (ProwlerExecRole)
    7. Next
    8. Next
    9. Review
    10. Check the box for "The following resource(s) require capabilities: [AWS::IAM::Role]" and Create Stack

3. Log into the AWS account where the Prowler Resources stack was deployed using SSM Connect and access the ProwlerEC2 Instance.
>Note: SSM Access is granted as part of the IAM Role which is provisioned and attached to the EC2 instance. If unable to connect, validate the subnet has Internet access and reboot the instance as the agent needs to >communicate with the AWS SSM endpoint.  
![InstanceConnect](docs/images/InstanceConnect.png)

4. Execute the prowler scan script to begin the assessment
>Note: Screen will be used to allow the prowler script to continue executing if console access is lost
    1. sudo -i
    2. screen
    3. cd /usr/local/bin/prowler
    4. ./prowler\_scan.sh

>Notes:
>1. The prowler\_scan.sh script is configured to assess all accounts in the AWS organization along with each region within those accounts. The script can be edited manually on the EC2 instance and variables adjusted >to tune the scan for specific use cases. Instructions are contained in the script at the top of the file.
>2. Scans take approx. 1 hour per AWS account to scan. Depending on the number of resources in the account, this time could be less or more. The bash script assesses multiple accounts in parallel.
>3. Optionally once the scan is running, force a screen detach by pressing control-a d . Screen will detach and you can close the EC2 connection and allow the assessment to proceed
>4. The screen process will keep the session running if the connection to the EC2 instance is dropped or detached.
    1. To resume a detached session, connect to the instance, sudo -i then screen -r
>5. If you would like to monitor status of the individual prowler scans,
    1. tail -f output/stdout-\<accountnumber\> in the prowler directory.

**PAUSE HERE UNTIL SCANS ARE COMPLETED**


5. Download prowler\_output-\<assessdate\>.zip from the S3 bucket, validate it opens, and then delete the S3 object from the bucket.
>Note: Having an empty bucket is required for resource removal when the Stack is deleted.

6. Stop the Prowler EC2 instance to prevent billing while the instance is idle.

7. Expand the zip file containing all of the output.
>Note: The stdout-\<accountid\> files included in the zip can be used for prowler execution review or troubleshooting, but will be not be processed for a report.

8. Open the "prowler-report-template.xlsm" excel document and select the "Prowler CSV" sheet. Delete all sample data except for Row 1 which is the header.

9. Open the "prowler-fullorgresults.csv" (or alternatively prowler-fullorgresults-accessdeniedfiltered.csv ) file with excel and remove the header row which should be the very first row of data.
>Note: The prowler-fullorgresults-accessdeniedfiltered.csv is a filtered version of the output file which has been generated as part of the prowler\_scan.sh file to remove common errors related to attempted scans on Control Tower resources.

The sorting process within the prowler\_scan.sh file should consolidate all headers into a single entry and then move it to the very top of the file. If it is not at the top, check the last very bottom.  

Delete the Header row as it is already present in the "prowler-report-template.xlsm" excel document  

e.g.\
PROFILE,ACCOUNT\_NUM,REGION,TITLE\_ID,CHECK\_RESULT,ITEM\_SCORED,ITEM\_LEVEL,TITLE\_TEXT,CHECK\_RESULT\_EXTENDED,CHECK\_ASFF\_COMPLIANCE\_TYPE,CHECK\_SEVERITY,CHECK\_SERVICENAME,CHECK\_ASFF\_RESOURCE\_TYPE,CHECK\_ASFF\_TYPE,CHECK\_RISK,CHECK\_REMEDIATION,CHECK\_DOC,CHECK\_CAF\_EPIC,CHECK\_RESOURCE\_ID,PROWLER\_START\_TIME,ACCOUNT\_DETAILS\_EMAIL,ACCOUNT\_DETAILS\_NAME,ACCOUNT\_DETAILS\_ARN,ACCOUNT\_DETAILS\_ORG,ACCOUNT\_DETAILS\_TAGS

10) Select all data from the Prowler generated output file and paste into the prowler-report-template file.  
Manually select all data from columns B through Y and copy to clipboard (control-c)
Switch to the "prowler-report-template.xlsm", go to the "Prowler CSV" sheet, click on Cell B2 and Control-v to paste all of the data into this document.

>Notes:

>1. Control-A doesn't work because we need to paste into row 2 and preserve the header in row 1.
>2. There may be "Access Denied" errors which may their way into the output, these should be deleted from the data before copying into the template so they don't appear in the findings. A couple options are >specified at the end of this document in the "Misc Options" section #1 which will allow you to process this data via command line. Use the filtered version to have the most common errors removed.
>3. The PROFILE, ACCOUNT\_DETAILS\_EMAIL, ACCOUNT\_DETAILS\_NAME, ACCOUNT\_DETAILS\_ARN, ACCOUNT\_DETAILS\_ORG, ACCOUNT\_DETAILS\_TAGS columns may be empty.

11) Validate that the document contains the customer's data and looks similar to the image below.  
![CustSanitizedData](docs/images/CustSanitizedData.png)

12) Change the format of the obfuscated ACCOUNT\_NUM column  
Excel doesn't properly display 12-digit AWS account numbers and formats it as an exponential number by default. It is recommended to change the formatting of the column to be number with 0 decimal places. Right click on column B and select "Format Cells…" This will be present in the findings as well and the same formatting change will be needed correct this.  
![FormatAdjust](docs/images/FormatAdjust.png)

13) Refresh Findings and graph pivot tables  
Select the "Findings" sheet at the bottom of the excel doc, click on A17 (Header of the pivot table) to select the PivotTable header, click "PivotTable Analyze" at the top toolbar, then click the dropdown next to Refresh, and click Refresh All. This will incorporate all new CSV output into the tables.  
![PivotRefresh](docs/images/PivotRefresh.png)

14) Review findings and provide to customer.  
The findings, severity, and customer review sheets provide details for analysis. If the excel is provided to the customer, delete as many tabs as possible to reduce complexity (Prowler CSV tab MUST remain or the pivot tables will fail). Copy the graphics you wish to use in a presentation document and then delete unneeded sheets. (E.g., Delete sheets: Instructions, Severity, Pass Fail, CIS Level, and Services & Accounts). Findings and Customer Review sheets will be one of the main areas where they can review consolidated findings and perform filtering.

15) If this Prowler deploy is not going to be utilized for future assessments, clean up the environment by deleting all Stacks and StackSets associated with this deployment.

# **Appendix** <a name="Appendix"></a>

- The /usr/local/bin/prowler/prowler\_scan.sh script drives the behavior of the Prowler based assessment. The default design is to generate a list of all AWS accounts within the AWS Organization and to scan up to 8 at a time including all regions within the account. This may not serve every use case and tunable variables have been included at the top of the script to allow for modification of this behavior.
    - Variables:
    1. PARALLELISM: Can be tuned to specify how many accounts to assess simultaneously. The instance size must be adjusted appropriately. Be aware of AWS Account level EC2 API throttling limits and to execute this script in an account with minimal workloads. C6i.2xlarge can sustain 9 parallel assessments. Utilize appropriately sized EC2 instance (4=c6i.large,6=c6i.xlarge, 8=c6i.2xlarge)
    2. AWSACCOUNT\_LIST: Specify the accounts to be assessed using one of the supported methods:
        1. Use the keyword allaccounts to generate a list of all accounts in the AWS Org
        2. Use the keyword inputfile to read in AWS Account IDs from a file (If using this mode, must also set AWSACCOUNT\_LIST\_FILE)
        3. Use a space separated list of AWS Account IDs
    3. AWSACCOUNT\_LIST\_FILE: If using AWSACCOUNT\_LIST="inputfile", specify the path to the file

    >Note: If the file is located in the /use/local/bin/prowler directory, specify the filename, else specify the full path. Account IDs can be specified on one line (space separated) or one Account ID per line

    4. REGION\_LIST: Specify regions (SPACE DELIMITED) if you wish to assess specific AWS regions or leave allregions to include all AWS regions.
    5. IAM\_CROSS\_ACCOUNT\_ROLE: The IAM Role name created for cross account access
    6. The prowler command within the for loop can be tuned to meet the needs of the assessment.  
    "./prowler -R ProwlerExecRole -A "$accountId" -M csv,html -T 43200 \> output/stdout-$accountId.txt 2\>&1"

    7. ACCOUNTID\_WITH\_NAME: By default, the value is true, the value of ACCOUNT\_NUM column in the final report is populated with Account Name in the format \<AccountId-AccountName\>. Changing the value to false will produce the report with ACCOUNT\_NUM=\<AccountId\>.

- Resource estimates: 4 parallel scans with c6i.large utilizes CPU at 80-90% ($2/day), 6 parallel scans with c6i.xlarge utilizes CPU at 85-90% ($4/day), 8 parallel scans with c6i.2xlarge utilizes CPU at 60-70% ($8/day). C5 was tested against T3 (Unlimited CPU Credits) and was only slightly more expensive, but reduced scan time. CPU should always remain under 92% while the script is executing else scan speed will be impacted.

- HTML files are output during the Prowler assessment and may be used as an alternative to the CSV. Due to the nature of HTML, it is not concatenated, processed, nor used directly in this procedure, however may be useful for individual account report review.

- If the results contain "Access Denied" errors, you will want to remove them from the findings before processing. The errors are typically due to external influencing permissions which blocked Prowler from assessing a particular resource. For example, some checks fail when reviewing Control Tower buckets "Access Denied getting bucket location for aws-controltower-logs-XXXXXXXXXXXX." These error messages should be removed from the consolidated output CSV file and then copied into the excel sheet.

    How to filter results and create a new file which EXCLUDES the row containing the pattern:
    >Note: Watch for ' when used at CLI. Copy and paste may use the wrong quote.
    Output lines which do NOT contain "Access Denied":

    Linux/Mac:
    grep -v -i "Access Denied getting bucket" myoutput.csv \> myoutput\_modified.csv

    Windows: (PowerShell)
    Select-String -Path myoutput.csv -Pattern 'Access Denied getting bucket' -NotMatch \> myoutput\_modified.csv

    >Note: Multiple patterns can be matched and processed at the same time.

    Linux/Mac: (Grep uses an escaped pipe)
    grep -v -i 'Access Denied getting bucket\|Access Denied Trying to Get' myoutput.csv \> myoutput\_modified.csv

    Windows: (Select-String uses a comma)
    Select-String -Path myoutput.csv -Pattern 'Access Denied getting bucket', 'Access Denied Trying to Get' -NotMatch \> myoutput\_modified.csv

- Single Threaded multi-account scanning:
    >Note "aws organizations list-accounts" can only be run in the management account or an AWS account which has been delegated admin (CloudFormation StackSet/IAM Access Analyzer/etc)

    1. Gather a list of all accounts in the AWS Org and execute prowler against all of them:
    ACCOUNTS\_IN\_ORGS=$(aws organizations list-accounts --output text --query 'Accounts[?Status==`ACTIVE`].Id')

    2. Execute prowler in a loop for all accounts stored in env variable ACCOUNTS\_IN\_ORGS:
    for accountId in $ACCOUNTS\_IN\_ORGS; do ./prowler -A $accountId -R ProwlerExecRole -M csv -n -T 43200 \> stdout-$accountId 2\>&1; done

- Single threaded scanning on specific accounts:
    1. Specify specific accounts to scan: (Manually specify AWS Account ID separated by whitespace)
    ACCOUNTS\_TO\_SCAN="111111111111 22222222222 33333333333"

    2. Execute prowler in a loop for accounts specified in the ACCOUNTS\_TO\_SCAN variable
    for accountId in $ACCOUNTS\_TO\_SCAN; do ./prowler -A $accountId -R ProwlerExecRole -M csv -n -T 43200 \> stdout-$accountId 2\>&1; done