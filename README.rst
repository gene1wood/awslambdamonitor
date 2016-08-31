AWS Lambda Monitor
==================

AWS Lambda Monitor is a small monitoring tool which runs in AWS Lambda.
The tool is triggered either regularly by a CloudWatch scheduled task or
on demand by an email triggered event. With this tool you can monitor
services on servers out on the internet for free and receive alert
emails when there are problems.

Why create another monitoring tool?
-----------------------------------

The rationale behind creating this tool (instead of using one of the
many existing monitoring tools in existence) is to take advantage of the
`AWS Lambda pricing model <https://aws.amazon.com/lambda/pricing/>`__ to
get free monitoring forever. AWS provides 37 days of 128MB memory Lambda
execution per month. Unlike the EC2 free tier, the Lambda free tier
doesn't expire after the first year.

The reason the tool uses email for input (triggering a monitoring run)
and output (alerting on problems) is that the `AWS SES pricing
model <https://aws.amazon.com/ses/pricing/>`__ allows for 1000 emails
per month. The alternative interface for AWS Lambda would be the `AWS
API Gateway <https://aws.amazon.com/api-gateway/pricing/>`__ which costs
$3.50/month.

How to build and upload awslambdamonitor to AWS
===============================================

Build and package virtualenv
----------------------------

To build the zip file containing the virtualenv, spin up an Amazon Linux
EC2 instance (as this is the environment that AWS Lambda functions run
in). Create the zip file as follows

::

    sudo yum groupinstall 'Development Tools'
    sudo yum install libyaml-devel libffi-devel openssl-devel
    virtualenv build-aws-lambda-monitor-environment
    build-aws-lambda-monitor-environment/bin/pip install pyOpenSSL paramiko ecdsa pycrypto python-whois PyYAML ndg-httpsclient pyasn1 requests
    pushd build-aws-lambda-monitor-environment/lib/python2.7/dist-packages/
    zip -r ~/awslambdamonitor.zip *
    popd

    pushd build-aws-lambda-monitor-environment/lib64/python2.7/dist-packages/
    zip -r ~/awslambdamonitor.zip *
    popd

    rm -rf build-aws-lambda-monitor-environment

scp fetch the file from the amazon linux machine
------------------------------------------------

Download the resulting zipped virtualenv from the EC2 instance and
destroy the instance.

Add the monitor to the zipped virtualenv
----------------------------------------

::

    zip --junk-paths awslambdamonitor.zip awslambdamonitor/monitor.py

Add your config to the zipped virtualenv
----------------------------------------

::

    zip --junk-paths awslambdamonitor.zip awslambdamonitor/monitor.yaml

Publish package to AWS Lambda and setup CloudWatch scheduled job
----------------------------------------------------------------

::

    AWS_ACCOUNT_ID=123456789012
    AWS_PROFILE=myprofilename
    AWS_REGION=us-west-2
    aws lambda create-function --function-name monitor --runtime python2.7 --timeout 30 --role arn:aws:iam::$AWS_ACCOUNT_ID:role/lambda_basic_execution --handler monitor.monitor --zip-file fileb://awslambdamonitor.zip  --profile $AWS_PROFILE --region $AWS_REGION
    aws lambda invoke --function-name monitor --log-type Tail --payload '{"account": "123456789012","region": "us-east-1","detail": {},"detail-type": "Scheduled Event","source": "aws.events","time": "1970-01-01T00:00:00Z","id": "cdc73f9d-aea9-11e3-9d5a-835b769c0d9c","resources": ["arn:aws:events:us-east-1:123456789012:rule/AWSLambdaMonitor5Minutes"]}'  --profile $AWS_PROFILE --region $AWS_REGION output.txt

    aws lambda update-function-code --function-name monitor --zip-file fileb://awslambdamonitor.zip --profile $AWS_PROFILE --region $AWS_REGION

    aws events put-rule --name AWSLambdaMonitor5Minutes --schedule-expression 'rate(5 minutes)' --state ENABLED --profile $AWS_PROFILE --region $AWS_REGION
    aws events put-rule --name AWSLambdaMonitorDaily --schedule-expression 'rate(1 day)' --state ENABLED --profile $AWS_PROFILE --region $AWS_REGION

    aws lambda add-permission --function-name monitor --statement-id AWSLambdaMonitor5MinutesID --action 'lambda:monitor' --principal events.amazonaws.com --source-arn arn:aws:events:$AWS_REGION:$AWS_ACCOUNT_ID:rule/AWSLambdaMonitor5Minutes --profile $AWS_PROFILE --region $AWS_REGION
    aws lambda add-permission --function-name monitor --statement-id AWSLambdaMonitorDailyID --action 'lambda:monitor' --principal events.amazonaws.com --source-arn arn:aws:events:$AWS_REGION:$AWS_ACCOUNT_ID:rule/AWSLambdaMonitorDaily --profile $AWS_PROFILE --region $AWS_REGION

    aws events put-targets --rule AWSLambdaMonitor5Minutes --targets '{"Id" : "AWSLambdaMonitor5Minutes-monitor", "Arn": "arn:aws:lambda:$AWS_REGION:$AWS_ACCOUNT_ID:function:monitor"}' --profile $AWS_PROFILE --region $AWS_REGION
    aws events put-targets --rule AWSLambdaMonitorDaily --targets '{"Id" : "AWSLambdaMonitorDaily-monitor", "Arn": "arn:aws:lambda:$AWS_REGION:$AWS_ACCOUNT_ID:function:monitor"}' --profile $AWS_PROFILE --region $AWS_REGION

Iterate on code by updating and uploading
-----------------------------------------

If you want to extend or modify the monitor you can update the running
code like this

::

    # Update the file in the zip archive 
    zip --junk-paths awslambdamonitor.zip awslambdamonitor/monitor.py

    # Upload the new zip file
    aws lambda update-function-code --function-name monitor --zip-file fileb://awslambdamonitor.zip --profile $AWS_PROFILE --region $AWS_REGION

If you want to change your configuration

::

    # Update the file in the zip archive 
    zip --junk-paths awslambdamonitor.zip awslambdamonitor/monitor.yaml

    # Upload the new zip file
    aws lambda update-function-code --function-name monitor --zip-file fileb://awslambdamonitor.zip --profile $AWS_PROFILE --region $AWS_REGION

Test Event
==========

Here is an example event that you can use in the AWS Lambda web console
to test the monitor

::

    {
      "account": "123456789012",
      "region": "us-east-1",
      "detail": {},
      "detail-type": "Scheduled Event",
      "source": "aws.events",
      "time": "1970-01-01T00:00:00Z",
      "id": "cdc73f9d-aea9-11e3-9d5a-835b769c0d9c",
      "resources": [
        "arn:aws:events:us-east-1:123456789012:rule/AWSLambdaMonitor5Minutes"
      ]
    }

