# This sample, non-production-ready python script process network analyzer results of a specific scope and outputs an csv for further processing and analysis.
# © 2022 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
# This AWS Content is provided subject to the terms of the AWS Customer Agreement available at
# http://aws.amazon.com/agreement or other written agreement between Customer and either
# Amazon Web Services, Inc. or Amazon Web Services EMEA SARL or both.

from errno import ENFILE
import json
import csv
import sys
import getopt
import os
import os.path



def main():
    FIELDS = ['account','region','vpc_id','subnet_id','instance_id','instance_arn','instance_name','resource_id','resource_arn','secgroup_id','sgrule_direction','sgrule_cidr','sgrule_protocol','sgrule_portrange']
    EXCLUSIONF = ''
    OUTPUTF = ''
    INPUTF = ''
    naa_exclusions = ''

    argv = sys.argv[1:]

    if len(sys.argv) == 1:
        print ("Pass required parameters with:")
        print ("REQUIRED: -i INPUTFILE")
        print ("REQUIRED: -o OUTPUTFILE")
        print ("REQUIRED: -e EXCLUSIONFILE")
        print ("HELP: -h")
        quit()

    try:
        opts, args = getopt.getopt(argv, "he:i:o:")
    except getopt.GetoptError:
        print ("Pass required parameters with:")
        print ("REQUIRED: -i INPUTFILE")
        print ("REQUIRED: -o OUTPUTFILE")
        print ("REQUIRED: -e EXCLUSIONFILE")
        print ("HELP: -h")
        quit()

    for opt, arg in opts:
        if opt == '-h':
            print ("Pass required parameters with:")
            print ("REQUIRED: -i INPUTFILE")
            print ("REQUIRED: -o OUTPUTFILE")
            print ("REQUIRED: -e EXCLUSIONFILE")
            print ("HELP: -h")
            quit()
        elif opt in ['-i']:
            INPUTF = arg
        elif opt in ['-o']:
            OUTPUTF = arg
        elif opt in ['-e']:
            EXCLUSIONF = arg

    # Opening NAA export JSON file
    if INPUTF:
        f = open(INPUTF)
    rows = []
    if os.path.exists(OUTPUTF):
        append_write = 'a' # append if already exists
    else:
        append_write = 'w' # make a new file if not

    with open(OUTPUTF, append_write) as csvfile:
        csvwriter = csv.writer(csvfile)
        if append_write == 'w':
            csvwriter.writerow(FIELDS)
        else:
            pass

        # returns JSON object as a dictionary
        data = json.load(f)
        # Iterating through the json object
        for Finding in data['AnalysisFindings']:
            #Initialize variables
            instance_id = "N/A"
            instance_arn = "N/A"
            instance_name = "N/A"
            account = "N/A"
            region = "N/A"
            vpci_id = "N/A"
            subnet_id = "N/A"
            resource_id = "N/A"
            resource_arn = "N/A"
            secgroup_id = "N/A"
            sgrule_direction = "N/A"
            sgrule_cidr = "N/A"
            sgrule_protocol = "N/A"
            sgrule_portrange = "N/A"
            skip_finding = False

            findingId = Finding['FindingId']
            findingcomponents = Finding['FindingComponents']
            for component in findingcomponents:
                if 'Component' in component:
                    if 'network-interface' in component['Component']['Arn']:
                        resource_id = component['Component']['Id']
                        resource_arn = component['Component']['Arn']
                if 'internet-gateway' in component['Component']['Arn']:
                    igw_id = component['Component']['Id']
                    igw_arn = component['Component']['Arn']
                if 'Vpc' in component:
                    if 'vpc' in component['Vpc']['Arn']:
                        vpc_id = component['Vpc']['Id']
                        vpc_arn = component['Vpc']['Arn']
                if 'security-group' in component['Component']['Arn']:
                    secgroup_id = component['Component']['Id']
                    secgroup_arn = component['Component']['Arn']
                    secgroup_name = component['Component']['Name']
                if 'SecurityGroupRule' in component:
                    if 'Cidr' in component['SecurityGroupRule']:
                        sgrule_cidr = component['SecurityGroupRule']['Cidr']
                        sgrule_direction = component['SecurityGroupRule']['Direction']
                        sgrule_protocol = component['SecurityGroupRule']['Protocol']
                    elif 'SecurityGroupId' in component['SecurityGroupRule']:
                        sgrule_cidr = component['SecurityGroupRule']['SecurityGroupId']
                        sgrule_direction = component['SecurityGroupRule']['Direction']
                        sgrule_protocol = component['SecurityGroupRule']['Protocol']
                    if 'PortRange' in component['SecurityGroupRule']:
                        sgrule_portrange = str(f"{component['SecurityGroupRule']['PortRange']['From']} to {component['SecurityGroupRule']['PortRange']['To']}")
                    elif sgrule_protocol == 'all':
                        sgrule_portrange = 'all'
                    else:
                        sgrule_portrange = ''
                if 'Subnet' in component:
                    if 'subnet' in component['Subnet']['Arn']:
                        subnet_id = component['Subnet']['Id']
                        subnet_arn = component['Subnet']['Arn']
                if 'AttachedTo' in component:
                    if 'instance' in component['AttachedTo']['Arn']:
                        instance_id = component['AttachedTo']['Id']
                        instance_arn = component['AttachedTo']['Arn']
                        instance_name = component['AttachedTo']['Name']
                split_arn = igw_arn.split(':')
                region = split_arn[3]
                account = split_arn[4]

            # Read in file of ENI exclusions (if it exists) so they are skipped from the output
            # Open file which contains ENI exclusions
            with open(EXCLUSIONF) as exclusioncsvfile:
                naa_exclusions = csv.reader(exclusioncsvfile, delimiter=',')
                for row in naa_exclusions:
                    if ((resource_id == row[0]) and (secgroup_id == row[1]) and (sgrule_cidr == row[2]) and (sgrule_portrange == row[3])):
                        skip_finding = True
                        continue

            if not skip_finding:
                rows.append([account,region,vpc_id,subnet_id,instance_id,instance_arn,instance_name,resource_id,resource_arn,secgroup_id,sgrule_direction,sgrule_cidr,sgrule_protocol,sgrule_portrange])
            skip_finding = False

        csvwriter.writerows(rows)

        # Closing file
        f.close()

if __name__ == "__main__":
    main()