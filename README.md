# Multi-Account Security Assessment via Prowler
Step by step instructions are provided (Prowler Assessment Procedure.md) to automate an assessment of AWS Accounts with the use of Prowler. 

This solution facilitates a multi-account assessment to processes multiple AWS accounts in parallel. All resources and EC2 buildout are deployed via CloudFormation. Once assessed, results are consolidated, expected error messages removed (e.g. Control Tower bucket restrictions), and findings packaged for use with an Excel sheet to process into an easily readable form.

The processed output can be used as part of a report which highlights potential areas of improvement around security controls.

There are many ways to deploy and utilize Prowler for an assessment, but this solution has been designed to allow a consultant to rapidly deploy the solution, gather findings, and utilize them as part of a security posture report.

As new versions of Prowler are released, they'll be validated for functionality, IAM permissions tuned as needed, and incorporated into the CloudFormation templates.

Files:

- Prowler Assessment Procedure.md: Step by step instructions for provisioning IAM Roles, Prowler Resources, and processing findings.

- prowler_scan.sh: 
    Bash script used for assessing multiple AWS accounts in parallel. This script is automatically deployed onto the EC2 instance in the folder /usr/local/bin/prowler via the prowler-resources.yaml CFT in userdata. By default, this script assumes the IAM role “ProwlerExecRole” in the management account to generate a list of member accounts in the AWS Org. The script then uses this list of accounts to begin an assessment of the accounts. As the accounts are assessed, they will output results in the prowler/outputs directory in CSV and HTML formats.  Once all accounts have been assessed, the individual CSV files will be concatenated, duplicate lines removed, and all output files zipped. Note: This script has tunable variables within the script itself (See appendix for more details). This script is provided independently from the CFT for reference.

- Prowler-resources.yaml: 
    A CFT which is deployed in the account where the prowler EC2 instance will be deployed.  This template will deploy all necessary dependencies in order for prowler to perform assessments across all accounts.  The IAM-ProwlerExecRole is dependent on this template being deployed first.  Note: If this stack is deleted and redeployed, the ProwlerExecRole StackSet will need to be re-deployed to rebuild the cross-account dependency between IAM Roles.

- IAM-ProwlerExecRole.yaml:
    A CFT to be deployed via StackSet across all member accounts (including the AWS Org Root/Management account). This will create an IAM Role which can be assumed by prowler during scanning.

- prowler-report-template.xlsm:
    An excel document for processing of findings.   Pivot tables allow for search capabilities, charts, and consolidated findings. Note: The excel document version must match with a supported version of prowler.

# Link to APG Artifact (Authorized Access Only)
https://apg-library.amazonaws.com/content/81ba9037-9958-4e4a-95b7-d68896075a5b
