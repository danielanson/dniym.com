from __future__ import print_function
import logging
import boto3
import re
import os
import json
import hashlib
import socket
from boto3.dynamodb.conditions import Key, Attr

DYNAMO_DB_TABLE = os.environ['DYNAMO_DB_TABLE']
DYNAMO_DB_INDEX_NAME = os.environ['DYNAMO_DB_INDEX_NAME']

logger = logging.getLogger()
logger.setLevel(logging.INFO)

logger.info("Loading function.")

def create_response(err, res=None, status_code=None):
    
    # This method sends response to api-gateway
    if not status_code:
        status_code = '400' if err else '200'
    print("Response status: {}, type: {}".format(status_code,
          type(status_code)))
    print("Res: {}, Err: {}".format(res, err))
    if status_code != 200:
        raise Exception("event_processor lambda failed.")
    response = {
        'statusCode': status_code,
        'body': err.message if err else json.dumps(res),
        'headers': {
            'Content-Type': 'application/json',
        },
    }
    return response


class EventProcessor:

    def __init__(self, phone_number, ip_address, logger):
        self.logger = logger
        self.sns_client = boto3.client('sns')
        self.DynamoDB_resource = boto3.resource('dynamodb')
        self.phone_number = phone_number
        self.ip_address = ip_address

    # validate 11 digit phone_number.  We dont write the number to the log!
    def validate_phone_number(self):
        regex = re.compile("\d{11}")
        match = regex.match(self.phone_number)
        if match:
            self.logger.info("Phone number is legit.")
            return True
        else:
            self.logger.info("Phone number verification failed.")
            return False

    def validate_ip_address(self):
        try:
            inet_aton = socket.inet_aton(self.ip_address)
            self.logger.info("IP address %s verified", self.ip_address)
        except Exception as err:
            self.logger.info("IP address %s failed verification",
                             self.ip_address)
            raise

    # Creates a SHA-1 hash of the IP and Phone Number as we dont store
    # the phone_number in the DB or the logs, it only lives in memory 
    # for the duration of the lambda.
    def create_sha1_hash(self):
        hash_object = hashlib.sha1(self.phone_number + self.ip_address)
        hex_dig = hash_object.hexdigest()
        if hex_dig:
            self.logger.info("sha1_hash: {}".format(hex_dig))
            return hex_dig
        else:
            return 0

    # spam_killer ensures 2 things:
    # 1)  customer cant sent more than 1 msg to a phone#/IP hash from an IP.
    # 2)  customer cant sent more than 1 req from an IP in X amount of time.
    def spam_killer(self, hash_hex):
        table = self.DynamoDB_resource.Table(DYNAMO_DB_TABLE)
        response = table.query(
            Select='COUNT',
            KeyConditionExpression=Key('sha1_hash').eq(hash_hex)
        )
        hex_hash_count = response['Count']
        self.logger.info("hex_hash_count: %s", hex_hash_count)
        response = table.query(
            IndexName=DYNAMO_DB_INDEX_NAME,
            Select='COUNT',
            KeyConditionExpression=Key('ip_address').eq(self.ip_address)
        )
        ip_address_count = response['Count']
        self.logger.info("ip_address_count: %s", ip_address_count)
        return (int(hex_hash_count), int(ip_address_count))
        
    def insert_dynamodb_record(self, hash_hex):
        table = self.DynamoDB_resource.Table(DYNAMO_DB_TABLE)
        table.put_item(Item={
                'sha1_hash': hash_hex,
                'ip_address': self.ip_address,
                'stat': 'Unprocessed'
                }
            )
        self.logger.info("DynamoDB record fields: sha1_hash: {}, IP: {}, stat: \
                         Unprocessed".format(hash_hex, self.ip_address))
        return True

    def send_SMS(self):

        response = self.sns_client.publish(
            PhoneNumber=self.phone_number,
            Message='dniym.com>\n\nYou know D, right?\ndniym.com',
            MessageAttributes={
                'AWS.SNS.SMS.SenderID': {
                    'DataType': 'String',
                    'StringValue': 'SENDERID'
                },
                'AWS.SNS.SMS.SMSType': {
                    'DataType': 'String',
                    'StringValue': 'Promotional'
                }
            }
        )
        self.logger.info(response)
        return

    def update_dynamodb_record(self, hash_hex):
        table = self.DynamoDB_resource.Table(DYNAMO_DB_TABLE)
        response = table.update_item(
            Key={
                'sha1_hash': hash_hex,
                'ip_address': self.ip_address
            },
            UpdateExpression='set stat = :p',
            ExpressionAttributeValues={
                ':p': "Processed",
            }
        )
        self.logger.info("Marked record as Processed")
        return True

def lambda_handler(event, context):

    phone_number = event["phone_number"]
    ip_address = event["ip_address"]
    try:
        ep = EventProcessor(phone_number, ip_address, logger)
    except Exception as err:
        return create_response(err, None, 400)

    if not ep.validate_phone_number():
        return create_response(None, {"message": "Phone number is bogus"},
                               400)

    try:
        ep.validate_ip_address()
    except Exception as err:
        return create_response(err, {"message": "Validate IP address failed."},
                                     None)

    hash_hex = ep.create_sha1_hash()
    if not hash_hex:
        return create_response(None, {"message": "sha1_hash creation failed."},
                                      400)

    try:
        (hex_id_count, ip_address_count) = ep.spam_killer(hash_hex)
        if (hex_id_count or ip_address_count):
            logger.info("Spam killer invoked.")
            return create_response(None, {"message": "Spam Killer invoked."},
                                   200)   
        else:
            pass
    except Exception as err:
        return create_response(err, {"message": "Error determining spam."},
                               200)

    try:
        ep.insert_dynamodb_record(hash_hex)
    except Exception as err:
        return create_response(err, {"message": "Dynamo DB reord creation \
                                     failed."}, 400)

    try:
        ep.send_SMS()
    except Exception as err:
        return create_response(err, None, 400)

    try:
        ep.update_dynamodb_record(hash_hex)
    except Exception as err:
        return create_response(err, {"message": "Dynamo DB reord update \
                                     failed."}, 400)

    return 'Message Sent.'
