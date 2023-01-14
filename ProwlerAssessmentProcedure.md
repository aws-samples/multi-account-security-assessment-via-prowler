# Multi-Account Security Assessment via Prowler with Batching and Post Processing

## Table of Contents

1. [Overview](#overview)
2. [Related Resources](#related-resources)
3. [Implementation Procedure](#implementation-procedure)
4. [Output Handling](#output-handling)
5. [Appendix](#appendix)

## Overview

Execution of prowler requires deployment of an IAM Role to all accounts being scanned, an IAM Role which the EC2 instance running prowler will utilize, the deployment of an EC2 instance running the prowler software, and an S3 bucket to store the output. This procedure has been validated with prowler versions 3.0.0-3.0.2.

## Related Resources

prowler_scan.sh: Bash script used for assessing multiple AWS accounts in parallel. This script is automatically deployed onto the EC2 instance in the folder /usr/local/bin/prowler via the prowler-resources.yaml CFT in userdata. By default, this script assumes the IAM role "ProwlerExecRole" in the management account to generate a list of member accounts in the AWS Org. The script then uses this list of accounts to begin an assessment of the accounts. As the accounts are assessed, they will output results in the prowler/outputs directory in CSV and HTML formats. Once all accounts have been assessed, the individual CSV files will be concatenated, duplicate lines removed, and all output files zipped. Note: This script has tunable variables within the script itself (See appendix for more details). This script is provided independently from the CFT for reference.

Prowler-resources.yaml: A CFT template which is deployed in the account where the prowler EC2 instance will be deployed. This template will deploy all necessary dependencies in order for prowler to perform assessments across all accounts. The IAM-ProwlerExecRole is dependent on this template being deployed first. Note: If this stack is deleted and redeployed, the ProwlerExecRole StackSet will need to be re-deployed to rebuild the cross-account dependency between IAM Roles.

IAM-ProwlerExecRole.yaml: A CFT template to be deployed via StackSet across all member accounts. This will create an IAM Role which can be assumed by prowler during scanning.

prowler-report-template.xlsm: An excel document for processing of findings. Pivot tables allow for search capabilities, charts, and consolidated findings. Note: The excel document version must match with a supported version of prowler.

## Implementation Procedure

1. Deploy the EC2 instance and supporting resources (prowler-resources.yaml)  
    >Note: When deploying the CFT template, it will provision an IAM Role, S3 Bucket with policy, SNS Topic, and EC2 instance which will be used by Prowler.
    1. Select an account where the Prowler EC2 instance will be provisioned (Security tooling focused AWS account recommended)
    2. Open the CloudFormation console
    3. Create Stack -\> With new resources
    4. Prerequisite - Prepare template: "Template is ready"
    5. Specify template: "Upload a template file" -\> "Choose File" -\> Browse for the template
        - Specify the prowler-resources.yaml template
    6. Next
    7. Specify stack details
        - StackSet name: Prowler-Resources
        - Parameters:
            - VPCId: Select a VPC in the account
            - SubnetId: Select a private subnet which has Internet access
                >Note: If a public subnet is selected, the EC2 instance will not provision as the CFT doesn't attach an EIP by default
            - InstanceType: Select an instance size based on the number of parallel assessments. Guidelines: 4=c6i.large, 6=c6i.xlarge, 8=c6i.2xlarge
            - InstanceImageId: Leave the default for Amazon Linux 2
            - KeyPairName: Specify the name of an existing KeyPair if using SSH for access (This is optional and can be left blank)
            - PermittedSSHInbound: If using SSH for access, specify a permitted CIDR
            - BucketName: Leave the default unless necessary
            - EmailAddress: Specify an email address for a SNS notification when Prowler completes the assessment and uploads the zip file to S3.
                >Note: The SNS subscription configuration must be confirmed prior to Prowler completing the assessment or a notification will not be sent.
            - IAMProwlerEC2Role: Leave the default unless necessary
            - IAMPRowlerExecRole: Leave the default unless necessary
            - Parallelism: Specify the number of parallel assessments to perform.
                >Note: Specify the proper InstanceType parameter value
    8. Next
    9. Next
    10. Review the summary
    11. Check the box for "The following resource(s) require capabilities: [AWS::IAM::Role]" and Create Stack
    12. Once the Stack has finished deploying, click the Outputs tab in the CloudFormation console and copy the ProwlerEC2Role ARN for use with the next CloudFormation template deploys.

2. Deploy the IAM cross account role to all AWS organization member accounts IAM-ProwlerExecRole.yaml)  
    >Note: The easiest way to do this is to utilize service-managed permissions when deploying the stack and deploying to the entire organization.
    > > This will require trust to be established between CloudFormation and the AWS Organization. If it is not already established, the CloudFormation console for StackSets will present a button which should be clicked and states "Enable trusted access with AWS Organizations to use service-managed permissions." This can be safely enabled (with the appropriate approval) without impacting existing stacks and can also be disabled at a later time via command line.

    1. Open the CloudFormation console
    2. Click StackSets
    3. Click "Create StackSet"
    4. Permissions: Service-managed permissions
    5. Prerequisite - Prepare template: "Template is ready"
    6. Specify template: "Upload a template file" -\> "Choose File" -\> Browse for the template.
        - Specify the IAM-ProwlerExecRole.yaml template.
    7. Next
    8. Specify StackSet details
        - StackSet name: IAM-ProwlerExecRole
        - Parameters:
          - AuthorizedARN: Specify the ProwlerEC2Role ARN which was provisioned as part of the prowler-resources.yaml stack.
          - ProwlerRoleName: Leave the default (ProwlerExecRole)
    9. Deployment targets: Leave "Deploy to organization" selected along with defaults
    10. Specify regions: Select a single region as IAM is global. (E.g., Use the region the Prowler EC2 Instance will be deployed in)
    11. OPTIONAL: Specify Deployment Options: Set BOTH "Maximum concurrent accounts" and "Failure tolerance" to a high number (E.g. 100) to have the stacks deploy to this number of AWS accounts simultaneously.
    12. Next
    13. Review the summary
    14. Check the box to approve "I acknowledge that AWS CloudFormation might create IAM resources with custom names."
    15. Submit
        >Monitor the "Stack instances" (Individual account status) and Operations (Overall) tabs to determine when the deploy is completed.

3. Deploy the IAM cross account role to the AWS organization management account (IAM-ProwlerExecRole.yaml)
    >Note: This deployment is direct to the management account as the StackSet deployed previously does not include the management account.
    1. Open the CloudFormation console
    2. Create Stack -\> With new resources
    3. Prerequisite - Prepare template: "Template is ready"
    4. Specify template: "Upload a template file" -\> "Choose File" -\> Browse for the template
       - Specify the IAM-ProwlerExecRole.yaml template
    5. Next
    6. Specify stack details
        - Stack name: IAM-ProwlerExecRole
        - Parameters:
          - AuthorizedARN: Specify the ProwlerEC2Role ARN which was provisioned as part of the Prowler-Resources stack.
          - ProwlerRoleName: Leave the default (ProwlerExecRole)
    7. Next
    8. Next
    9. Review the summary
    10. Check the box for "The following resource(s) require capabilities: [AWS::IAM::Role]" and Create Stack

4. Log into the AWS account where the Prowler Resources stack was deployed using SSM Connect and access the ProwlerEC2 Instance.
    >Note: SSM Access is granted as part of the IAM Role which is provisioned and attached to the EC2 instance. If unable to connect, validate the subnet has Internet access and reboot the instance as the agent needs to communicate with the AWS SSM endpoint.  

    ![InstanceConnect](docs/images/InstanceConnect.png)

5. Execute the prowler scan script to begin the assessment
    >Note: Screen will be used to allow the prowler script to continue executing if console access is lost.  Wait for the Prowler assessment to complete before continuing with Output handling

    ```bash
    sudo -i
    screen
    cd /usr/local/bin/prowler
    ./prowler_scan.sh
    ```

>Notes:

- The prowler_scan.sh script is configured to assess all accounts in the AWS organization along with each region within those accounts. The script can be edited manually on the EC2
instance and variables adjusted to tune the scan for specific use cases. Instructions are contained in the script at the top of the file.
- Scans take approx. 1 hour per AWS account to scan. Depending on the number of resources in the account, this time could be less or more. The bash script assesses multiple accounts in parallel.
- Optionally once the scan is running, force a screen detach by pressing control-a d . Screen will detach and you can close the EC2 connection and allow the assessment to proceed
- The screen process will keep the session running if the connection to the EC2 instance is dropped or detached.
  - To resume a detached session, connect to the instance, sudo -i then screen -r
- If you would like to monitor status of the individual prowler scans,
  - tail -f output/stdout-\<accountnumber\> in the prowler directory.

## Output Handling

>Note: The Prowler assessment must already be completed before continuing with this section.  The zip file will be present in the S3 bucket, and if SNS configured, an email delivered.

1. Download prowler_output-\<assessdate\>.zip from the S3 bucket, validate it opens, and then delete the S3 object from the bucket.
    >Note: Having an empty bucket is required for resource removal when the Stack is deleted.

2. Stop the Prowler EC2 instance to prevent billing while the instance is idle.

3. Expand the zip file containing all of the output.
    >Note: The stdout-\<accountid\> files included in the zip can be used for prowler execution review or troubleshooting, but will be not be processed for a report.

4. Prepare the PivotTable Excel Template for environment data  
    Open the "prowler-report-template.xlsm" excel document and select the "Prowler CSV" sheet  
    Delete all sample data except for Row 1 which is the header
    >Note: If asked whether to delete the query associated with the data being removed, click no to prevent problems with the PivotTable.

5. Open the output data from the Prowler assessment  
    Open the "prowler-fullorgresults-accessdeniedfiltered.txt" (or alternatively prowler-fullorgresults.txt) file with excel  
    Instruct Excel to convert the data into columns by delimiting with the semicolon.  
        Select Column A, Click the Excel "Data" menu item, Click "Text to Columns", Select "Delimited", Next, Select "Semicolon", click "Finish"
    Delete the header row which should be the very first row of data.
    >Note: The prowler-fullorgresults-accessdeniedfiltered.txt is a filtered version of the output file which has been generated as part of the prowler_scan.sh file to remove common errors related to attempted scans on Control Tower resources.

    The sorting process within the prowler_scan.sh file should consolidate all headers into a single entry and then move it to the very top of the file. If it is not at the top, check the last very bottom.  

    Delete the Header row as it is already present in the "prowler-report-template.xlsm" excel document  

    e.g.  
    ASSESSMENT_START_TIME   FINDING_UNIQUE_ID   PROVIDER    CHECK_ID    CHECK_TITLE CHECK_TYPE  STATUS  STATUS_EXTENDED SERVICE_NAME  
    SUBSERVICE_NAME SEVERITY    RESOURCE_TYPE   RESOURCE_DETAILS    RESOURCE_TAGS   DESCRIPTION RISK    RELATED_URL REMEDIATION_RECOMMENDATION_TEXT  
    REMEDIATION_RECOMMENDATION_URL  REMEDIATION_RECOMMENDATION_CODE_NATIVEIAC   REMEDIATION_RECOMMENDATION_CODE_TERRAFORM   REMEDIATION_RECOMMENDATION_CODE_CLI REMEDIATION_RECOMMENDATION_CODE_OTHER   CATEGORIES  DEPENDS_ON  RELATED_TO  NOTES   PROFILE ACCOUNT_ID  ACCOUNT_NAME    ACCOUNT_EMAIL   ACCOUNT_ARN ACCOUNT_ORG ACCOUNT_TAGS    REGION  RESOURCE_ID RESOURCE_ARN  

6. Select all data from the Prowler generated output file and paste into the prowler-report-template file.  
    - Manually select all data from columns A through the last column (Currently AK) and copy to clipboard
    - Switch to the "prowler-report-template.xlsm", go to the "Prowler CSV" sheet, click on Cell A2 and to paste all of the data into this document.

    >Notes:
    >
    > > - Control-A doesn't work because we need to paste into row 2 and preserve the header in row 1.
    > > - There may be "Access Denied" errors which may their way into the output, these should be deleted from the data before copying into the template so they don't appear in the findings. A couple options are specified in the Appendix of this document for removing Access Denied errors via command line.
    > > - It is recommended to use the prowler-fullorgresults-accessdeniedfiltered.csv file which has already been processed to remove the most common errors.
    > > - Some columns may be empty in the output.

7. Validate that the document contains the customer's data and looks similar to the image below.  
![CustSanitizedData](docs/images/CustSanitizedData.png)

8. Refresh Findings and graph pivot tables  
Select the "Findings" sheet at the bottom of the excel doc, click on A17 (Header of the pivot table) to select the PivotTable header, click "PivotTable Analyze" at the top toolbar, then click the dropdown next to Refresh, and click Refresh All. This will incorporate all new CSV output into the tables and tabs.  
![PivotRefresh](docs/images/PivotRefresh.png)

9. Change the format of the AWS Account numbers to number so they are shown properly  
Excel doesn't properly display 12-digit AWS account numbers and formats it as an exponential number by default. It is recommended to change the formatting of the column to be number with 0 decimal places. Right click on column A and select "Format Cells…" This will be present in the findings as well and the same formatting change will be needed correct this.  
![FormatAdjust](docs/images/FormatAdjust.png)

>Note: Excel will remove starting zeros from AWS Account IDs by default.  If an AWS account ID is LESS THAN 12 characters, it begins with 0

10. Review findings and provide to customer.  
The findings, severity, and customer review sheets provide details for analysis. If the excel is provided to the customer, delete as many tabs as possible to reduce complexity (Prowler CSV tab MUST remain or the pivot tables will fail). Copy the graphics you wish to use in a presentation document and then delete unneeded sheets. (E.g., Delete sheets: Instructions, Severity, Pass Fail, CIS Level, and Services & Accounts). Findings and Customer Review sheets will be one of the main areas where they can review consolidated findings and perform filtering.

11. If this Prowler deploy is not going to be utilized for future assessments, clean up the environment by deleting all Stacks and StackSets associated with this deployment.

## Appendix

1. The /usr/local/bin/prowler/prowler_scan.sh script drives the behavior of the Prowler based assessment. The default design is to generate a list of all AWS accounts within the AWS Organization and to scan up to 8 at a time including all regions within the account. This may not serve every use case and tunable variables have been included at the top of the script to allow for modification of this behavior.
    - PARALLELISM: Can be tuned to specify how many accounts to assess simultaneously. The instance size must be adjusted appropriately. Be aware of AWS Account level EC2 API throttling limits and to execute this script in an account with minimal workloads. C6i.2xlarge can sustain 9 parallel assessments. Utilize appropriately sized EC2 instance (4=c6i.large,6=c6i.xlarge, 8=c6i.2xlarge)
    - AWSACCOUNT_LIST: Specify the accounts to be assessed using one of the supported methods:
      - Use the keyword allaccounts to generate a list of all accounts in the AWS Org
      - Use the keyword inputfile to read in AWS Account IDs from a file (If using this mode, must also set AWSACCOUNT_LIST_FILE)
      - Use a space separated list of AWS Account IDs
    - AWSACCOUNT_LIST_FILE: If using AWSACCOUNT_LIST="inputfile", specify the path to the file
            >Note: If the file is located in the /use/local/bin/prowler directory, specify the filename, else specify the full path. Account IDs can be specified on one line (space separated) or one Account ID per line
    - REGION_LIST: Specify regions (SPACE DELIMITED) if you wish to assess specific AWS regions or leave allregions to include all AWS regions.
    - IAM_CROSS_ACCOUNT_ROLE: The IAM Role name created for cross account access
    - ACCOUNTID_WITH_NAME: By default, the value is true, the value of ACCOUNT_NUM column in the final report is populated with Account Name in the format \<AccountId-AccountName\>. Changing the value to false will produce the report with ACCOUNT_NUM=\<AccountId\>.
    - S3_BUCKET: The S3 bucket which will be used for Prowler report upload
    - The prowler command within the for loop can also be tuned to meet the needs of the assessment.  
        "./prowler -R ProwlerExecRole -A "$ACCOUNTID" -M csv,html -T 43200 \> output/stdout-$ACCOUNTID.txt 2\>&1"

2. Resource estimates: 4 parallel scans with c6i.large utilizes CPU at 80-90% ($2/day), 6 parallel scans with c6i.xlarge utilizes CPU at 85-90% ($4/day), 8 parallel scans with c6i.2xlarge utilizes CPU at 60-70% ($8/day). C5 was tested against T3 (Unlimited CPU Credits) and was only slightly more expensive, but reduced scan time. CPU should always remain under 92% while the script is executing else scan speed will be impacted.

3. HTML files are output during the Prowler assessment and may be used as an alternative to the CSV. Due to the nature of HTML, they are not concatenated, processed, nor used directly in this procedure, however may be useful for individual account report review.

4. If the results contain "Access Denied" errors, you will want to remove them from the findings before processing. The errors are typically due to external influencing permissions which blocked Prowler from assessing a particular resource. For example, some checks fail when reviewing Control Tower buckets "Access Denied getting bucket location for aws-controltower-logs-XXXXXXXXXXXX." These error messages should be removed from the consolidated output CSV file and then copied into the excel sheet.  

    How to filter results by removing rows which contain a pattern and outputting the results to a new file:

    - Linux/Mac:  

        ```bash
        grep -v -i "Access Denied getting bucket" myoutput.csv > myoutput_modified.csv
        ```

    - Windows: (PowerShell)  

        ```powershell
        Select-String -Path myoutput.csv -Pattern 'Access Denied getting bucket' -NotMatch > myoutput_modified.csv
        ```

    **Multiple patterns can be matched and processed at the same time:**  

    - Linux/Mac: (Grep uses an escaped pipe)  

        ```bash
        grep -v -i 'Access Denied getting bucket\|Access Denied Trying to Get' myoutput.csv > myoutput_modified.csv
        ```

    - Windows: (PowerShell: Select-String uses a comma)  

        ```powershell
        Select-String -Path myoutput.csv -Pattern 'Access Denied getting bucket', 'Access Denied Trying to Get' -NotMatch > myoutput_modified.csv
        ```

5. Single Threaded multi-account scanning:
    >Gather a list of all accounts in the AWS Org and execute Prowler in a loop for all accounts stored in env variable ACCOUNTS_IN_ORGS  
    Note: "aws organizations list-accounts" can only be run in the management account or an AWS account which has been delegated admin (CloudFormation StackSet/IAM Access Analyzer/etc)  

    ```bash
    ACCOUNTS_IN_ORGS=$(aws organizations list-accounts --output text --query 'Accounts[?Status==`ACTIVE`].Id')  
    for accountId in $ACCOUNTS_IN_ORGS; do ./prowler -A $accountId -R ProwlerExecRole -M csv,html -n -T 43200 \> stdout-$accountId 2\>&1; done  
    ```

6. Single threaded scanning on specific accounts:
    >Specify specific accounts to scan: (Manually specify AWS Account ID separated by whitespace) and then execute Prowler in a loop for accounts specified in the ACCOUNTS_TO_SCAN variable

    ```bash
    ACCOUNTS_TO_SCAN="111111111111 22222222222 33333333333"  
    for accountId in $ACCOUNTS_TO_SCAN; do ./prowler -A $accountId -R ProwlerExecRole -M csv,html -n -T 43200 \> stdout-$accountId 2\>&1; done
    ```
