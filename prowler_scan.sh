#!/bin/bash
#
#
# Prowler multi-account assessment script:
#   Used to drive the assessment of AWS accounts via Prowler, post-processing the output reports
#   and optimizing the effort involved via automation.
#
# Script version: 2.87
#
# Tunable parameters to review:
#   1) PARALLELISM: Can be tuned to specify how many accounts to assess simultaneously.
#       The instance size must be adjusted appropriately.
#       Be aware of AWS Account level EC2 API Throttling limits and to execute this script in an account with minimal workloads.
#       C6i.2xlarge can sustain 9 parallel assessments.
#       Utilize appropriately sized EC2 instance (4=c6i.large,6=c6i.xlarge, 8=c6i.2xlarge)
#   2) AWSACCOUNT_LIST: Specify the accounts to be assessed using one of the supported methods:
#       Use the keyword allaccounts to generate a list of all accounts in the AWS Org
#       Use the keyword inputfile to read in AWS Account IDs from a file (If using this mode, must also set AWSACCOUNT_LIST_FILE)
#       Use a space separated list of AWS Account IDs
#   3) AWSACCOUNT_LIST_FILE: If using AWSACCOUNT_LIST="inputfile", specify the path to the file
#   4) REGION_LIST: Specify regions (SPACE DELIMITED) if you wish to assess specific AWS regions
#       or leave allregions to include all AWS regions.
#   5) IAM_CROSS_ACCOUNT_ROLE: The IAM Role name created for cross account access
#   6) ACCOUNTID_WITH_NAME: By default, the value is true, the value of ACCOUNT_NUM column in the final report is populated with Account Name 
#       in the format <AccountId-AccountName>. Changing the value to false will produce the report with ACCOUNT_NUM=<AccountId>. 
#   7) S3_BUCKET: The S3 bucket which will be used for Prowler report upload.
#       This is set by default to the S3 bucket provisioned during deployment.
#   8) The prowler command within the for loop can be tuned to meet the needs of the assessment.
#       "./prowler -R ProwlerExecRole -A ""  -M csv,html -T 43200 > output/stdout-$ACCOUNTID.txt 2>&1"
#       See Prowler documentation for all options.
#########################################

#Variables which can be modified: (In most cases, scanning all accounts and all regions is preferred for a complete assessment)

#Adjust PARALLELISM to adjust the number of parallel scans 
PARALLELISM="8"

#Specify accounts to be assessed using one of the supported methods:
#  Use the keyword allaccounts to generate a list of all accounts in the AWS Org
#  Use the keyword inputfile to read in AWS Account IDs from a file
#  Use a space separated list of AWS Account IDs
AWSACCOUNT_LIST="allaccounts"
#AWSACCOUNT_LIST="inputfile"
#AWSACCOUNT_LIST="123456789012 210987654321"

#If using AWSACCOUNT_LIST="inputfile", specify the path to the file:
#  If the file is located in the /use/local/bin/prowler directory, specify the filename, else specify the full path
#  Account IDs can be specified on one line (space separated) or one Account ID per line
#AWSACCOUNT_LIST_FILE="file_with_account_ids

#Specify the regions to have assessed (space separated) or use the keyword allregions to include all regions:
REGION_LIST="allregions"
#REGION_LIST="us-east-1 us-east-2"

#Specify an IAM Role to use for cross account access in the target accounts (Execution Role):
IAM_CROSS_ACCOUNT_ROLE="ProwlerExecRole"

#Specify whether to output Account ID with Account Name in the final report.
ACCOUNTID_WITH_NAME=true

S3_BUCKET="SetBucketName"
#########################################

# CleanUp Last Ran Prowler Reports if they exist
rm -rf output/*

# CleanUp prowler_output.zip from previous run if it exists
rm -rf prowler_output.zip

# Create output folder for first time scan with redirected stout
mkdir -p output

#Create default aws cli config file for the user executing prowler.  The EC2 IAM Profile will grant appropriate permissions
aws configure set region us-east-1

# Unset environment variables if they exist and utilize IAM Role attached to the EC2 instance
unset_aws_environment() {
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}
unset_aws_environment

# Determine the executing account AWS Number and Partition
CALLER_IDENTITY_ARN=$(aws sts get-caller-identity --output text --query "Arn")
AWSPARTITION=$(echo "$CALLER_IDENTITY_ARN" | cut -d: -f2)
EXECACCOUNT=$(echo "$CALLER_IDENTITY_ARN" | cut -d: -f5)
echo ""
echo "AWS account Prowler is executing from: $EXECACCOUNT"
echo ""

# Assume Role in Managment account and export session credentials
management_account_session() {
    AWSMANAGEMENT=$(aws organizations describe-organization --query Organization.MasterAccountId --output text)
    echo "AWS organization Management account: $AWSMANAGEMENT"

    unset_aws_environment
    ROLE_SESSION_CREDS=$(aws sts assume-role --role-arn arn:"$AWSPARTITION":iam::"$AWSMANAGEMENT":role/"$IAM_CROSS_ACCOUNT_ROLE" --role-session-name ProwlerRun --output json)
    AWS_ACCESS_KEY_ID=$(echo "$ROLE_SESSION_CREDS" | jq -r .Credentials.AccessKeyId)
    AWS_SECRET_ACCESS_KEY=$(echo "$ROLE_SESSION_CREDS" | jq -r .Credentials.SecretAccessKey)
    AWS_SESSION_TOKEN=$(echo "$ROLE_SESSION_CREDS" | jq -r .Credentials.SessionToken)
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}

#Monitor the number of background processes and return to task execution for loop when bg jobs are less than PARALLELISM limit
process_monitor() {
    while [ "$(jobs | wc -l)" -ge $PARALLELISM ]
    do
        sleep 10
    done
}

if [ "$AWSACCOUNT_LIST" = "allaccounts" ]; then
    # Lookup All Accounts in AWS Organization
    management_account_session
    ACCOUNTS_TO_PROCESS=$(aws organizations list-accounts --output text --query 'Accounts[?Status==`ACTIVE`].Id')
    echo ""
elif [ "$AWSACCOUNT_LIST" = "inputfile" ]; then
    if [ -e $AWSACCOUNT_LIST_FILE ]; then
        echo "Reading External File: $AWSACCOUNT_LIST_FILE"
        ACCOUNTS_TO_PROCESS=$(cat $AWSACCOUNT_LIST_FILE)
    else
        echo "External file $AWSACCOUNT_LIST_FILE not located. Please validate the file/path and update the AWSACCOUNT_LIST_FILE variable."
        exit 0
    fi
else
    ACCOUNTS_TO_PROCESS=$AWSACCOUNT_LIST
fi

# Display account and region selection
echo ""
if [ "$AWSACCOUNT_LIST" = "allaccounts" ]; then
    echo "AWS Accounts being processed: All accounts in the AWS organization."
    echo "$ACCOUNTS_TO_PROCESS"
else
    echo "AWS Accounts being processed: Specified AWS accounts below."
    echo "$ACCOUNTS_TO_PROCESS"
fi

echo ""
echo "AWS regions being processed:"
if [ "$REGION_LIST" == "allregions" ]; then
    echo "All AWS regions"
else
    echo $REGION_LIST
fi

echo ""
echo "All stdout from prowler scans will be redirected to output/stdout-accountId.txt"
echo "As specific account assessments are completed, additional accounts will be assessed from the list"
echo ""

# Run Prowler against selected accounts and regions
if [ "$REGION_LIST" == "allregions" ]; then
    for ACCOUNTID in $ACCOUNTS_TO_PROCESS; do
        test "$(jobs | wc -l)" -ge $PARALLELISM && process_monitor || true
        {
            # Unset AWS Profile Variables
            unset_aws_environment
            echo -e "Assessing AWS Account: $ACCOUNTID with all AWS regions using Role: $IAM_CROSS_ACCOUNT_ROLE on $(date)"
            # Run Prowler
            ./prowler -R $IAM_CROSS_ACCOUNT_ROLE -A "$ACCOUNTID" -M csv,html -T 43200 > output/stdout-$ACCOUNTID.txt 2>&1 
        } &
    done
else
    for ACCOUNTID in $ACCOUNTS_TO_PROCESS; do
        test "$(jobs | wc -l)" -ge $PARALLELISM && process_monitor || true
        {
            # Unset AWS Profile Variables
            unset_aws_environment
            echo -e "Assessing AWS Account: $ACCOUNTID with regions: $REGION_LIST using Role: $IAM_CROSS_ACCOUNT_ROLE on $(date)"
            # Run Prowler with -f and scans regions specified in the $REGION_LIST variable
            ./prowler -R $IAM_CROSS_ACCOUNT_ROLE -A "$ACCOUNTID" -M csv,html -f "$REGION_LIST" -T 43200 > output/stdout-$ACCOUNTID.txt 2>&1 
        } &
    done
fi

# Wait for All Prowler Processes to finish
wait
echo ""
echo "Prowler assessments have been completed against all accounts"
echo ""

#Unset the STS AssumeRole session and revert to permissions via the EC2 attached IAM Role
unset_aws_environment

# Prowler Output Post-Processing
echo "======================================================================================"
echo "Prowler Output Post-Processing"
echo "======================================================================================"
echo ""

# Below logic is to reset the variable ACCOUNTID_WITH_NAME
if $ACCOUNTID_WITH_NAME; then
    echo "ACCOUNTID_WITH_NAME flag is ON, verifying to ensure AWS Org. is configured and can be queried to get list of accounts."
    management_account_session
    IS_ACCOUNT_PART_OF_AWS_ORG=$(aws organizations describe-organization);
    if [ "$IS_ACCOUNT_PART_OF_AWS_ORG" == "" ]; then
        # Account where prowler is executed is not part of the AWS Organizations.
        # Change the value of the variable ACCOUNTID_WITH_NAME to false.
        echo "AWS Org was not found! Skipping report generation with Account Name (Resetting the flag ACCOUNTID_WITH_NAME to false)."
        ACCOUNTID_WITH_NAME=false;
    fi
    # Verfiy AWS org. can be queried to get list of accounts.
    if $ACCOUNTID_WITH_NAME; then
        rm -f output/accts.txt # Delete previously generated accounts list file if exists.
        aws organizations list-accounts | jq -r '[.Accounts[] | {Account: .Id, Arn: .Arn, Email: .Email, Name: .Name, AccountName: (.Id + "-" + .Name), Status: .Status, JoinedMethod: .JoinedMethod, JoinedTimestamp: .JoinedTimestamp}]' | jq -r '(.[0] | keys_unsorted) as $keys | $keys, map([.[ $keys[] ]])[] | @csv' | sed 's/\"//g' > output/accts.txt    
        if [ ! -f "output/accts.txt" ]; then
            echo "Failed getting list of Accounts from AWS Org! Skipping report generation with Account Name (Resetting the flag ACCOUNTID_WITH_NAME to false)."
            ACCOUNTID_WITH_NAME=false;
        fi
    fi
    unset_aws_environment
    echo "Completed."
    echo ""
fi 

CONSOLIDATED_REPORT=output/prowler-fullorgresults.csv;
if $ACCOUNTID_WITH_NAME; then    
    # Concatenating all output csv files into a single file for use with Excel and replace account_num with <AccountId-AccountName>
    echo "Concatenating all output csv files into a single file for use with Excel and replacing account_num with <AccountId-AccountName>..."
    counter=1; 
    rm -f output/prowler-fullorgresults-temp.csv; 
    for fileName in output/prowler-*.csv ; do 
        if [[ "$fileName" != "output/prowler-fullorgresults.csv" && "$fileName" != "output/prowler-fullorgresults-accessdeniedfiltered.csv" && "$fileName" != "output/prowler-fullorgresults-with-acct-name.csv" && "$fileName" != "output/prowler-fullorgresults-raw.csv" ]]; then  
            echo "Processing the file $fileName to replace AccountId with Name."
            acctId=$(awk 'BEGIN{FS=OFS=","} {if(NR==2) {print $2}}' $fileName); 
            acctName=$(awk -v var=$acctId '$1 == var {print $5}' FS=, output/accts.txt); 
            if [[  "$counter" == "1" ]]; then
                # Header line
                awk 'NR==1 {print; exit}' $fileName > $CONSOLIDATED_REPORT;
                ((counter+=1));
            fi
            # echo "$counter    $fileName    $acctId    $acctName"; # debug statement
            if [ "$acctName" == "" ]; then
                echo "Skipping Account Name replacement for the file $fileName, REASON: Account Name for the account $acctId not found in the file output/accts.txt"
                awk 'NR>1' $fileName > output/PROCESS.csv; 
                rm -f output/PROCESS.csv;
            else
                echo "Performing Account Name replacement for the file $fileName, ACCOUNT_NUM=$acctId with new value $acctName"
                awk 'NR>1' $fileName > output/PROCESS.csv; 
                awk -F, -v var="$acctName" '{$2=var;}1' OFS=, output/PROCESS.csv >> output/prowler-fullorgresults-temp.csv;
                rm -f output/PROCESS.csv;
            fi            
        fi  
    done ; 
    cat output/prowler-fullorgresults-temp.csv | sort | uniq >> $CONSOLIDATED_REPORT; 
    rm -f output/prowler-fullorgresults-temp.csv;     
    echo "Completed."
    echo ""
else
    #Concatenating all output csv files into a single file for use with Excel
    echo "Concatenating all output csv files into a single file for use with Excel..."
    cat output/prowler-*.csv | sort | uniq > output/prowler-fullorgresults-raw.csv
    echo "Completed."
    echo ""

    # Move the final line in the file (Header) to the top for easier location in Excel
    awk '{a[NR]=$0} END {print a[NR]; for (i=1;i<NR;i++) print a[i]}' output/prowler-fullorgresults-raw.csv > $CONSOLIDATED_REPORT

    # Remove the initial concatenated raw file
    rm -rf output/prowler-fullorgresults-raw.csv    
fi # end of if ACCOUNTID_WITH_NAME is true.

#Perform processing to remove common "Access Denied" errors from output while preserving the "full" output
echo "Creating an optional filtered version of the concatenate output for use with Excel..."
grep -v -i 'Access Denied getting bucket\|Access Denied Trying to Get\|InvalidToken' $CONSOLIDATED_REPORT > output/prowler-fullorgresults-accessdeniedfiltered.csv
echo "Completed."
echo ""

#Zip output results into a single file for download (stdout-* includes stdout and can be reviewed for troubleshooting)
OUTPUT_SUFFIX=$(date +%m-%d-%Y-%H-%M);
echo "Zipping output results into a single file for download. Output File: prowler_output.zip"
zip prowler_output-$OUTPUT_SUFFIX.zip output/*.csv output/*.txt output/*.html
echo "Completed."
echo ""

#Upload Prowler Report to S3
aws s3 cp prowler_output-$OUTPUT_SUFFIX.zip s3://$S3_BUCKET