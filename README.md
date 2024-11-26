# AYGPmvp
Proyecto Aygo mvp.
System that uses AWS Config and Lambda to enforce security policies (e.g., encryption, access controls) on AWS resources.
Add automated notification and remediation workflows using AWS EventBridge and SNS.

## Step 1
Determine the specific IT governance policies to enforce. For this example:
* Policy 1: Ensure all S3 buckets have default encryption enabled.
* Policy 2: Ensure EC2 instances are tagged with Environment and Owner tags.
* Policy 3: Monitor and remediate public access to resources (S3 buckets).
## Step 2
Set Up AWS Services
### Set Up AWS Config
AWS Config will continuously monitor resources for compliance with specified rules.
#### Enable AWS Config:
* Go to the AWS Config console.
* Choose "Set up AWS Config."
* Select the resources to monitor (e.g., S3, EC2).
* Configure an S3 bucket to store configuration snapshots.
#### Define Config Rules
* Use managed rules in this case: s3-bucket-encryption-enabled, 

![1](https://github.com/JuanC-358/AYGPmvp/blob/main/assets/1.png)

* Create a rule to validate Ec2 Tags
1. create a Lambda function with this code to validate the tags.
 ```python
import json
import boto3

def lambda_handler(event, context):
    ec2_client = boto3.client('ec2')

    invoking_event = json.loads(event['invokingEvent'])
    instance_id = invoking_event['configurationItem']['resourceId']

    response = ec2_client.describe_tags(
        Filters=[{'Name': 'resource-id', 'Values': [instance_id]}]
    )

    required_tags = ['Environment', 'Owner']

    tags = {tag['Key']: tag['Value'] for tag in response.get('Tags', [])}
    missing_tags = [tag for tag in required_tags if tag not in tags]

    if missing_tags:
        compliance_type = "NON_COMPLIANT"
        annotation = f"Faltan las siguientes etiquetas: {', '.join(missing_tags)}"
    else:
        compliance_type = "COMPLIANT"
        annotation = "Todas las etiquetas requeridas están presentes."
    return {
        "compliance_type": compliance_type,
        "annotation": annotation
    }

```
![2](https://github.com/JuanC-358/AYGPmvp/blob/main/assets/2.png)

* Add the new rule in Aws config.

![3](https://github.com/JuanC-358/AYGPmvp/blob/main/assets/3.png)

### Set Up EventBridge
EventBridge will trigger actions based on rule compliance events.
* Specify events from AWS Config indicating resource non-compliance.
 ```json
{
  "source": ["aws.config"],
  "detail": {
    "complianceType": ["NON_COMPLIANT"]
  }
}
```
* Configure EventBridge to invoke a Lambda function for remediation.
### Set Up SNS
SNS will send notifications about compliance violations.
1. Create an SNS topic.
2. Subscribe your email or SMS to receive notifications.
3. Configure EventBridge to publish compliance events to this SNS topic.

![6](https://github.com/JuanC-358/AYGPmvp/blob/main/assets/6sns.png)

## Step 3: Develop Remediation Logic with Lambda
Write Lambda functions to automatically remediate policy violations.
### Create a Lambda Function for S3 Bucket Encryption
1. implement the function.
 ```python
import boto3

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    bucket_name = event['detail']['resourceId']
    
    try:
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                }]
            }
        )
        return f"Encryption enabled for bucket {bucket_name}"
    except Exception as e:
        return f"Error enabling encryption: {str(e)}"

```
![4](https://github.com/JuanC-358/AYGPmvp/blob/main/assets/4s3.png)

2. Deploy the function and grant it the required permissions, in this case: s3:PutBucketEncryption.
### Create a Lambda Function for EC2 Tagging
Enforce tagging for EC2 instances:
 ```python
import boto3

def lambda_handler(event, context):
    ec2 = boto3.client('ec2')
    instance_id = event['detail']['resourceId']
    
    try:
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {'Key': 'Environment', 'Value': 'Production'},
                {'Key': 'Owner', 'Value': 'Admin'}
            ]
        )
        return f"Tags added for instance {instance_id}"
    except Exception as e:
        return f"Error tagging instance: {str(e)}"

```

![5](https://github.com/JuanC-358/AYGPmvp/blob/main/assets/5ec2.png)

2. Deploy the function.

## Step 4: Set Up Automated Notifications
Configure SNS to notify administrators of compliance violations and remediation results.
1. Add an SNS publish step in the Lambda functions to send updates.
 ```python
import boto3

sns = boto3.client('sns')
topic_arn = 'arn:aws:sns:your-region:your-account-id:your-topic'

sns.publish(
    TopicArn=topic_arn,
    Message=f"Remediation applied: {details}",
    Subject="AWS Compliance Notification"
)

```
![7](https://github.com/JuanC-358/AYGPmvp/blob/main/assets/7.png)
![8](https://github.com/JuanC-358/AYGPmvp/blob/main/assets/8.png)

## Step 5: Test the System
### Create Non-Compliant Resources
* Create an S3 bucket without encryption.
* Launch an EC2 instance without tags.
![9](https://github.com/JuanC-358/AYGPmvp/blob/main/assets/9.png)
### Trigger and Test Remediation
* Verify that EventBridge triggers Lambda functions for non-compliant resources.
![10](https://github.com/JuanC-358/AYGPmvp/blob/main/assets/10.png)
![11](https://github.com/JuanC-358/AYGPmvp/blob/main/assets/11.png)
* Check that Lambda functions remediate the issues and send notifications via SNS.
### Perform Stress Tests
* Use  AWS Fault Injection Simulator or Locust to simulate large-scale resource creation.
* Monitor performance and latency of compliance checks.
## Implications of doing future work
### Optional Enhancements
#### Add More Policies:
* IAM role compliance (e.g., enforce MFA).
* RDS encryption and backup checks.
#### Advanced Notifications:
* Use AWS Chatbot to notify teams on Slack or Microsoft Teams.
#### CI/CD Integration:
* Automate deployment of compliance rules using AWS CodePipeline or Terraform.


