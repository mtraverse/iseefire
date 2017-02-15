import boto3
import os
import gzip
import json
from sys import argv

script, conf_file = argv

# To be defined later, set multiple ways to pass variables (file command arguments)

jsonparams = open(conf_file, 'r')
variables = json.load(jsonparams)
jsonparams.close()

bucket = variables['bucket']
archive = variables['archive']
tmpdir = variables['tmpdir']
reqregion = variables['reqregion']
reqsig = variables['reqsig']
authorized_regions = variables['authorized_regions']
snstopic = variables['snstopic']
#authorized_services = variable['autorized_services']
#authorized_actions = variables['autorized_actions'] <--- To be defined later, pass forbidden actions as a variable
authorized_actions = ['Describe*', 'Get*', 'ListKeys']

basicsession = boto3.session.Session()
s3client = boto3.client('s3', region_name=reqregion, config=boto3.session.Config(signature_version=reqsig))
s3resource = boto3.resource('s3', region_name=reqregion, config=boto3.session.Config(signature_version=reqsig))
snsclient = boto3.client('sns', region_name=reqregion, config=boto3.session.Config(signature_version=reqsig))

available_regions = basicsession.get_available_regions('s3', 'aws')
unauthorized_regions = []

for region in available_regions:
    if (region not in authorized_regions):
        unauthorized_regions.append(region)

paginator = s3client.get_paginator('list_objects')
page_iterator = paginator.paginate(Bucket = bucket)

filecount = 0
recordcount = 0
suspiciousactions = 0
actions = []

# Add a test to stop if rhere's non entry (with function try?)

def define_action( action ):
    if (action[-1] == '*'):
        action = [action.split('*')[0], len(action.split('*')[0]), 'R']
    elif (action[0] == '*'):
        action = [action.split('*')[1], len(action.split('*')[1]), 'L']
    else:
        action = action
    return action


for action in authorized_actions:
    actions.append(define_action(action))
    print (actions)
#    actions = actions.append(action_detail)
#print (actions)
raw_input()

for page in page_iterator:

    for file in page["Contents"]:
#        recordsinfilecount = 0
        filecount = filecount + 1
        filename = file["Key"].rsplit('/')

        print ('Working on file: %d' % filecount)
        print ('Downloading logfile ' + filename[-1])

        s3client.download_file(bucket, file["Key"], tmpdir + filename[-1])

        print ('Updating attributes on logfile ' + filename[-1])

        os.chmod(tmpdir + filename[-1],0777)

        print ('Extracting logfile ' + filename[-1])

        gzfile = gzip.open(tmpdir + filename[-1], 'r')
        filecontent = gzfile.read()
        gzfile.close()
        jsonfilecontent = json.loads(filecontent)

# Switch search order
#        print (jsonfilecontent)
#        print (type(jsonfilecontent))
#        print (jsonfilecontent['Records'])
#        print (type(jsonfilecontent['Records']))

        for record in jsonfilecontent['Records']:
            recordcount = recordcount + 1
#            recordsinfilecount = recordsinfilecount + 1
            print ('Working on record: %d' % recordcount)
            if (record['awsRegion']) in unauthorized_regions:
                print ('Use of unauthorized region ' + record['awsRegion'] + ' found')
                apicall = actions_split(authorized_actions)
                print (apicall)
                raw_input()
                if (record['eventName'])[0:8] <> 'Describe':
                    suspiciousactions = suspiciousactions + 1
                    print ('Use of unauthorized action ' + record['eventName'] + ' found in region ' + record['awsRegion'])
#                    for region in unauthorized_regions:
#                    if filecontent.find(region) <> -1:
#                        print ('Use of unauthorized region ' + region + ' found')
#                        jsonfile = open(tmpdir + filename[-1] + '.json', 'w')
#                        json.dump(filecontent, jsonfile)
#                        jsonfile.close()
                    snsclient.publish(TopicArn=snstopic, Message='Date: ' + record['eventTime'] + '\n' + 'Operation: ' + record['eventName'] + '\n' + 'Region: ' + record['awsRegion'] + '\n' + 'Source: ' + record['eventSource'] + '\n' + 'Source IP: ' + record['sourceIPAddress'] + '\n' + 'User: ' + record['userIdentity']['userName'] + '\n\n'  'found in file: ' + filename[-1] + '\n\n' + 'Full Record: ' + '\n' + str(record), Subject='Use of unauthorized region ' + record['awsRegion'] + ' found')

        print ('Deleting local cached logfile ' + tmpdir + filename[-1])

        os.remove(tmpdir + filename[-1])

#        print ('Archiving logfile ' + filename[-1])

#        s3resource.Object(bucket, archive + '/' + filename[-1]).copy_from(CopySource=bucket + '/' + file["Key"])

        print ('Deleting logfile ' + filename[-1] + ' from source location')

        s3client.delete_object(Bucket=bucket, Key=file["Key"])

snsclient.publish(TopicArn=snstopic, Message=str(recordcount) + ' record(s) checked within ' + str(filecount) + ' file(s).' + '\n' + str(suspiciousactions) + ' suspicious action(s) found in activity.', Subject='CloudTrail logs audit summary')
