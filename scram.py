
import termcolor
import pathlib
import boto3
import json
import sys
import os

def usage():
    pass

# Print a colorful status message
def status(message, status):
    message = termcolor.colored(message, 'cyan')
    status  = termcolor.colored('pass', 'green')
    if status:
        termcolor.colored('fail','red')
    print(f"{message:50s} ...  [ {status:s} ]")

# Register any domains if needed
def route53(session, domains):
    for domain in domains:
        status("Route53 domain " + domain, True)
    pass

# Create an ACM certificate for all of the domains
def acm(session, domains):
    pass

# Create an S3 bucket
def s3(session, domains):
    s3_client = session.client('s3')

    domain = domains[0]
    bucket = {}
    try:
        bucket = s3_client.head_bucket(Bucket = domain)
        status("S3 Bucket " + domain, True)
    except:
        status("S3 Bucket " + domain, False)

        # Create a bucket
        s3_client.create_bucket(Bucket = domain)#,  CreateBucketConfiguration={'LocationConstraint': 'us-east-1'})

        # Disable BPA
        s3_client.put_public_access_block(
            Bucket = domain,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': False,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': False,
                'RestrictPublicBuckets': False
            }
        )

        # Set bucket policy to make it fully public
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PublicReadGetObject",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{domain}/*"
                }
            ]
        }
        s3_client.put_bucket_policy(
            Bucket = domain,
            Policy = json.dumps(bucket_policy)
        )

        status("S3 Bucket " + domain, True)
    pass

# Create a cloudfront distribution
def cloudfront(session, domains):
    pass

if __name__ == "__main__":
    # Our working directory is always our main site name
    domains = [ pathlib.Path.cwd().name.lower() ]

    # Plus anything we got on the command line
    if len(sys.argv) > 1:
        domains += sys.argv[1:]

    # And anything in an 'aliases' file
    try:
        domains += map(str.strip, open("aliases").readlines())

    except:
        pass

    # Normalize everything to lowercase
    domains = list(map(str.lower, domains))

    # The primary domain is the first one
    primary_domain = domains[0]

    # Create a boto3 session
    session = boto3.Session()

    # Check if we have these domains registered
    route53(session, domains)

    # Check if we have a certificate with all of these names on it
    acm(session, domains)

    # Create the route53 verification records
    route53_verify(session, domains)

    # Confirm that the certificate has been verified
    acm_verify(session)

    # Make sure an S3 bucket exists
    s3_bucket(session, domains)

    # S3 logging bucket
    s3_log(session, domains)

    # Now create a cloudfront distribution
    cloudfront(session, domains)

    # S3 permissions
    s3_perms(session, domains)

    # At long last, sync the files to S3


#
#{
#    "Version": "2012-10-17",
#    "Statement": {
#        "Sid": "AllowCloudFrontServicePrincipalReadOnly",
#        "Effect": "Allow",
#        "Principal": {
#            "Service": "cloudfront.amazonaws.com"
#        },
#        "Action": "s3:GetObject",
#        "Resource": "arn:aws:s3:::<S3 bucket name>/*",
#        "Condition": {
#            "StringEquals": {
#                "AWS:SourceArn": "arn:aws:cloudfront::111122223333:distribution/<CloudFront distribution ID>"
#            }
#        }
#    }
#}
