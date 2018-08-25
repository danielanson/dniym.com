from __future__ import print_function
import logging
import boto3
import os
import json
from boto3.dynamodb.conditions import Key, Attr

DYNAMO_DB_TABLE = os.environ['DYNAMO_DB_TABLE']

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

def truncate_table():
    DynamoDB_resource = boto3.resource('dynamodb')
    table = DynamoDB_resource.Table(DYNAMO_DB_TABLE)
    response = table.scan(
        Select='ALL_ATTRIBUTES',
        FilterExpression=Attr('stat').eq("Processed"),
    )
    count = int(response['Count'])
    logger.info("{} items found.".format(count))
    if not count:
        logger.info("No items found.  Returning.")
        return
    for i in response['Items']:
        res=table.delete_item(
            Key={
                "sha1_hash": i['sha1_hash'],
                "ip_address": i['ip_address']
            }
        )
    logger.info("Deleted {} item(s)".format(count))
    return

def lambda_handler(event, context):

    try:
        truncate_table()
    except Exception as err:
        return create_response(err, None, 400)

    return "Table truncated."
