# Copyright 2025 Colm MacCárthaigh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Dict, Set, List, Optional
import os
import sys

import termcolor
import argparse
import hashlib
import pathlib
import boto3
import json
import time
import uuid

def usage() -> None:
    """Print usage instructions for the script."""
    print("Usage: scram.py [--register|--setup] [additional_domains...]")
    print("\nThis script manages AWS infrastructure for hosting a static website.")
    print("\nModes:")
    print("    --register: Register new domains with Route 53")
    print("    --setup: Set up AWS infrastructure for existing domains")
    print("\nThe primary domain is automatically determined from the current directory name.")
    print("\nAdditional domains can be specified in two ways:")
    print("    1. As command line arguments")
    print("    2. In an 'aliases' file in the current directory")
    print("\nExample:")
    print("    $ mkdir example.com")
    print("    $ cd example.com")
    print("    $ scram.py --register www.example.com blog.example.com")
    print("    $ scram.py --setup www.example.com blog.example.com")
    print("\nNote: AWS credentials must be configured in your environment.")

def status(message: str, code: str) -> None:
    """Print a colorful status message.
    
    Args:
        message: The message to display
        success: Whether the operation was successful
    """
    print(f"{message:71s} [ {code:s} ]")

def success(message: str) -> None:
    """Print a success message.
    
    Args:
        message: The message to display
    """
    status(message, termcolor.colored('pass', 'green'))
    
def failure(message: str) -> None:
    """Print a failure message.
    
    Args:
        message: The message to display
    """
    status(message, termcolor.colored('fail', 'red'))

def progress(message: str) -> None:
    """Print a progress message in yellow.
    
    Args:
        message: The progress message to display
    """
    status(f"  {message}", termcolor.colored('....','yellow')) 

# Register domains with Route 53
def route53_register(session: boto3.Session, domains: List[str]) -> None:
    """Register domains with Route 53.
    
    Args:
        session: AWS boto3 session
        domains: List of domains to register
    """
    route53_client = session.client('route53domains')
    
    # List existing domains
    try:
        existing_domains = route53_client.list_domains()
        if existing_domains['Domains']:

            # Get contact details from the most recent domain
            most_recent = existing_domains['Domains'][0]
            contact_details = route53_client.get_domain_detail(
                DomainName=most_recent['DomainName']
            )
            #print(contact_details)
            contact_info = contact_details['AdminContact']
            
            if contact_info:
                print("Found existing contact details:")
                print(f"    Name: {contact_info.get('FirstName', '')} {contact_info.get('LastName', '')}")
                print(f"    Organization: {contact_info.get('OrganizationName', '')}")
                print(f"    Address: {contact_info.get('AddressLine1', '')}")
                print(f"    City: {contact_info.get('City', '')}, {contact_info.get('State', '')} {contact_info.get('ZipCode', '')}")
                print(f"    Country: {contact_info.get('CountryCode', '')}")
                print(f"    Phone: {contact_info.get('PhoneNumber', '')}")
                print(f"    Email: {contact_info.get('Email', '')}")
                print()
                
                while True:
                    response = input("Would you like to use these contact details? (yes/no): ").lower()
                    if response in ['yes', 'no']:
                        break
                    print("Please enter 'yes' or 'no'")
                
                if response == 'yes':
                    contact_template = {
                        'FirstName': contact_info.get('FirstName', ''),
                        'LastName': contact_info.get('LastName', ''),
                        'ContactType': 'PERSON',
                        'OrganizationName': contact_info.get('OrganizationName', ''),
                        'AddressLine1': contact_info.get('AddressLine1', ''),
                        'City': contact_info.get('City', ''),
                        'State': contact_info.get('State', ''),
                        'CountryCode': contact_info.get('CountryCode', ''),
                        'ZipCode': contact_info.get('ZipCode', ''),
                        'PhoneNumber': contact_info.get('PhoneNumber', ''),
                        'Email': contact_info.get('Email', '')
                    }
                else:
                    contact_template = None
            else:
                contact_template = None
        else:
            contact_template = None
    except Exception as e:
        print(f"Warning: Could not fetch existing domains: {str(e)}")
        contact_template = None
    
    # If no contact template was set, prompt for details
    if not contact_template:
        print("\nPlease provide contact details for domain registration:")
        contact_template = {
            'FirstName': input("First Name: "),
            'LastName': input("Last Name: "),
            'ContactType': 'PERSON',
            'OrganizationName': input("Organization Name: "),
            'AddressLine1': input("Address Line 1: "),
            'City': input("City: "),
            'State': input("State/Province: "),
            'CountryCode': input("Country Code (e.g., US): "),
            'ZipCode': input("ZIP/Postal Code: "),
            'PhoneNumber': input("Phone Number (e.g., +1.1234567890): "),
            'Email': input("Email: ")
        }

    for domain in domains:
        try:
            # Check if domain is available
            availability = route53_client.check_domain_availability(DomainName=domain)
            
            if availability['Availability'] == 'AVAILABLE':
                # Register the domain using the contact template
                response = route53_client.register_domain(
                    DomainName=domain,
                    DurationInYears=1,
                    AutoRenew=True,
                    AdminContact=contact_template,
                    RegistrantContact=contact_template,
                    TechContact=contact_template,
                    PrivacyProtectAdminContact=True,
                    PrivacyProtectRegistrantContact=True,
                    PrivacyProtectTechContact=True
                )
                
                success(f"Domain registration {domain}")
                progress(f"    Operation ID: {response['OperationId']}")
                progress("    Note: Domain registration can take up to 3 days to complete.")
                
            elif availability['Availability'] == 'UNAVAILABLE':
                failure(f"Domain registration {domain}")
                progress(f"    Error: Domain {domain} is not available for registration")
            else:
                failure(f"Domain registration {domain}")
                progress(f"    Error: Domain {domain} availability check failed: {availability['Availability']}")
                
        except Exception as e:
            failure(f"Domain registration {domain}")
            progress(f"    Error: {str(e)}")

# Check for hosted zones in Route 53
def route53_zones(session: boto3.Session, domains: List[str]) -> Dict[str, Dict]:
    """Check for hosted zones in Route 53.
    
    Args:
        session: AWS boto3 session
        domains: List of domains to check
        
    Returns:
        Dictionary mapping domain names to their hosted zones
    """
    route53_client = session.client('route53')
    hosted_zones = {}
    
    try:
        for domain in domains:
            # List all hosted zones
            response = route53_client.list_hosted_zones_by_name(DNSName = domain)
        
            # Create a map of domain names to their hosted zones
            for zone in response['HostedZones']:
                # Remove trailing dot from zone name for comparison
                zone_name = zone['Name'].rstrip('.')

                if domain != zone_name:
                    continue

                hosted_zones[zone_name] = zone
            
    except Exception as e:
        failure("Route53 zone listing")
        progress(f"    Error: {str(e)}")

    # Check each domain against the hosted zones
    for domain in domains:
        if domain in hosted_zones:
            success(f"Route53 zone {domain}")
        else:
            failure(f"Route53 zone {domain}")
            progress(f"    Warning: No hosted zone found for domain: {domain}")
    
    return hosted_zones

# Create an ACM certificate for all of the domains
def acm(session: boto3.Session, domains: List[str], hosted_zones: Dict[str, Dict]) -> Optional[str]:
    """Create an ACM certificate for all of the domains.
    
    Args:
        session: AWS boto3 session
        domains: List of domains to create certificate for
        hosted_zones: Dictionary of hosted zones
        
    Returns:
        Certificate ARN if successful, None otherwise
    """
    acm_client = session.client('acm')
    route53_client = session.client('route53')
    
    # First, try to find an existing certificate that covers all domains
    certificates = acm_client.list_certificates(CertificateStatuses=['ISSUED', 'PENDING_VALIDATION'])
    matching_cert = None
    
    for cert in certificates['CertificateSummaryList']:
        cert_arn = cert['CertificateArn']
        cert_details = acm_client.describe_certificate(CertificateArn=cert_arn)
        
        # Get all domain names from the certificate
        cert_domains = set()
        cert_domains.update(cert_details['Certificate']['DomainName'])
        cert_domains.update(cert_details['Certificate'].get('SubjectAlternativeNames', []))
        
        # Check if all our domains are covered
        if all(domain in cert_domains for domain in domains):
            matching_cert = cert_details['Certificate']
            break
    
    if matching_cert:
        success("ACM Certificate found")
        return matching_cert['CertificateArn']

    else:    
    
        # If no matching certificate found, create a new one
        try:
            # Prepare the request parameters
            request_params = {
                'DomainName': domains[0],
                'ValidationMethod': 'DNS'
            }
        
            # Only add SubjectAlternativeNames if there are additional domains
            if len(domains) > 1:
                request_params['SubjectAlternativeNames'] = domains[1:]
        
            response = acm_client.request_certificate(**request_params)
            
            cert_arn = response['CertificateArn']
            success("ACM Certificate requested")
            print(f"    Certificate ARN: {cert_arn}")
            
        except Exception as e:
            failure("ACM Certificate request")
            print(f"    Error: {str(e)}")
            return None
        
    # Get the validation options
    cert_details = acm_client.describe_certificate(CertificateArn=cert_arn)

    if cert_details['Certificate']['Status'] == 'ISSUED':
        success("ACM Certificate issued")
        return cert_arn

    validation_options = cert_details['Certificate']['DomainValidationOptions']
    # Add DNS validation records to Route 53
    for option in validation_options:
        domain = option['DomainName']
        record = option['ResourceRecord']
        zone_id = hosted_zones[domain]['Id']
    
        try:
            # Create the validation record
            route53_client.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={
                    'Changes': [{
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                    'Name': record['Name'],
                    'Type': record['Type'],
                    'TTL': 300,
                    'ResourceRecords': [{
                        'Value': record['Value']
                                        }]
                        }
                    }]
                }
            )
            success(f"DNS validation record for {domain}")
        
        except Exception as e:
            failure(f"DNS validation record for {domain}")
            print(f"    Error: {str(e)}")
        
        # Wait for certificate validation
        max_attempts = 300  # 10 minutes maximum
        attempts = 0
        
        while attempts < max_attempts:
            cert_details = acm_client.describe_certificate(CertificateArn=cert_arn)
            cert_status = cert_details['Certificate']['Status']
            
            if cert_status == 'ISSUED':
                success("ACM Certificate validation")
                return cert_arn
            elif cert_status == 'FAILED':
                failure("ACM Certificate validation")
                print(f"    Error: {cert_details['Certificate']['FailureReason']}")
                return None
            
            # Check if all validation records are valid
            all_valid = True
            for option in cert_details['Certificate']['DomainValidationOptions']:
                if option['ValidationStatus'] != 'SUCCESS':
                    all_valid = False
                    break
            
            if all_valid:
                print("\nAll validation records are valid, waiting for final issuance...")
            
            attempts += 1
            time.sleep(2)  # Wait 2 seconds between checks
        
        failure("ACM Certificate validation time out")
        return None

# Create S3 buckets
def s3_buckets(session: boto3.Session, bucket: str, log_bucket: str) -> None:
    """Create S3 buckets for website content and logs.
    
    Args:
        session: AWS boto3 session
        bucket: Name of the main S3 bucket
        log_bucket: Name of the log S3 bucket
    """
    s3_client = session.client('s3')

    try:
        s3_client.head_bucket(Bucket = bucket)
        success("S3 Bucket " + bucket)
    except:
        failure("S3 Bucket " + bucket)

        # Create a bucket
        progress(f"    Creating S3 bucket {bucket}")
        s3_client.create_bucket(Bucket = bucket)#,  CreateBucketConfiguration={'LocationConstraint': 'us-east-1'})

    try:
        s3_client.head_bucket(Bucket = log_bucket)
        success("S3 Bucket " + log_bucket)
    except:
        failure("S3 Bucket " + log_bucket)

        # Create a bucket
        progress(f"    Creating S3 bucket {log_bucket}")
        s3_client.create_bucket(Bucket = log_bucket)#,  CreateBucketConfiguration={'LocationConstraint': 'us-east-1'})
        

def s3_policy(session: boto3.Session, bucket: str, log_bucket: str,distribution: str) -> None:
    """Set up S3 bucket policies for CloudFront and CloudWatch access.
    
    Args:
        session: AWS boto3 session
        bucket: Name of the main S3 bucket
        log_bucket: Name of the log S3 bucket
        distribution: CloudFront distribution ID
    """
    s3_client = session.client('s3')
    log_bucket = bucket + '-logs'
    account_id = session.client('sts').get_caller_identity()['Account']
            
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
           {
                "Sid": "SCRAM-AllowCloudFrontServicePrincipalReadOnly",
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudfront.amazonaws.com"
                },                                   
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {
                    "StringEquals": {
                        "AWS:SourceArn": f"arn:aws:cloudfront::{account_id}:distribution/{distribution}"
                    }
                }
            }
        ]
    }
    
    s3_client.put_bucket_policy(
        Bucket = bucket,
        Policy = json.dumps(bucket_policy)
    )

    success("S3 Bucket Policy " + bucket)
    
    # Set log bucket policy to allow CloudWatch Logs to write logs
    log_bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SCRAM-AllowCloudWatchLogsWrite",
                "Effect": "Allow",
                "Principal": {
                "Service": "delivery.logs.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": f"arn:aws:s3:::{log_bucket}/AWSLogs/aws-account-id={account_id}/CloudFront/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control",
                    "aws:SourceAccount": f"{account_id}"
                },
                "ArnLike": {
                    "aws:SourceArn": f"arn:aws:logs:us-east-1:{account_id}:delivery-source:SCRAM-cloudfront-{distribution}"
                }
            }
        }
        ]
    }
    
    s3_client.put_bucket_policy(
        Bucket = log_bucket,
        Policy = json.dumps(log_bucket_policy)
    )
    
    success("S3 Log Bucket Policy " + log_bucket)

    
def cloudfront_distribution(session: boto3.Session, domains: List[str]) -> Optional[str]:
    """Find an existing CloudFront distribution that covers all domains.
    
    Args:
        session: AWS boto3 session
        domains: List of domains to check
        
    Returns:
        Distribution ID if found, None otherwise
    """
    cloudfront_client = session.client('cloudfront')
    
    # First, try to find an existing distribution that covers all domains
    distributions = cloudfront_client.list_distributions()
    matching_dist = None
    
    if 'DistributionList' in distributions and 'Items' in distributions['DistributionList']:
        for dist in distributions['DistributionList']['Items']:
            # Get distribution details
            dist_details = cloudfront_client.get_distribution(Id=dist['Id'])
            config = dist_details['Distribution']['DistributionConfig']
            
            # Check if all our domains are in the aliases
            if 'Aliases' in config and 'Items' in config['Aliases']:
                dist_domains = set(alias.lower() for alias in config['Aliases']['Items'])
                if all(domain in dist_domains for domain in domains):
                    matching_dist = dist_details['Distribution']
                    break
    
    if matching_dist:
        success(f"CloudFront Distribution found {matching_dist['Id']}")
        return matching_dist['Id']

    return None
                
# Create a cloudfront distribution
def cloudfront(session: boto3.Session, domains: List[str], cert_arn: str) -> Optional[str]:
    """Create a CloudFront distribution for the domains.
    
    Args:
        session: AWS boto3 session
        domains: List of domains to create distribution for
        cert_arn: ACM certificate ARN
        
    Returns:
        Distribution ID if successful, None otherwise
    """
    cloudfront_client = session.client('cloudfront')
    dist_id = cloudfront_distribution(session, domains)
    
    if dist_id:
        return dist_id
    
    # Get the S3 bucket name (first domain)
    s3_bucket = domains[0]
    s3_log_bucket = s3_bucket + '-logs'
        
    # Create distribution configuration
    distribution_config = {
        'CallerReference': str(uuid.uuid4()),  # Unique string
        'Aliases': {
            'Quantity': len(domains),
            'Items': domains
        },
        'DefaultRootObject': 'index.html',
        'Origins': {
            'Quantity': 1,
            'Items': [{
                'Id': f'S3-{s3_bucket}',
                'DomainName': f'{s3_bucket}.s3.amazonaws.com',
                'S3OriginConfig': {
                    'OriginAccessIdentity': ''
                }
            }]
        },
        'DefaultCacheBehavior': {
            'TargetOriginId': f'S3-{s3_bucket}',
            'ForwardedValues': {
                'QueryString': False,
                'Cookies': {'Forward': 'none'}
            },
            'TrustedSigners': {
                'Enabled': False,
                'Quantity': 0
            },
            'ViewerProtocolPolicy': 'redirect-to-https',
            'MinTTL': 60 * 60 * 24 * 30 # 30 days
        },
        'CacheBehaviors': {'Quantity': 0},
        'CustomErrorResponses': {'Quantity': 0},
        'Comment': f'Distribution for {", ".join(domains)}',
        'Enabled': True,
        'PriceClass': 'PriceClass_All',  
        'ViewerCertificate': {
            'ACMCertificateArn': cert_arn,
            'SSLSupportMethod': 'sni-only',
            'MinimumProtocolVersion': 'TLSv1.2_2021'
        },
        'HttpVersion': 'http2and3',
        'IsIPV6Enabled': True
    }

    try:
        # Create the distribution
        response = cloudfront_client.create_distribution(
            DistributionConfig=distribution_config
        )

        dist_id = response['Distribution']['Id']
        success(f"CloudFront Distribution {dist_id} created")

    except Exception as e:
        failure("CloudFront Distribution creation")
        print(f"    Error: {str(e)}")
        return None
    
    # Wait for distribution to be fully deployed
    progress("Waiting for CloudFront distribution to be fully deployed...")
    
    max_attempts = 300  # 10 minutes maximum
    attempts = 0
        
    while attempts < max_attempts:
        dist_details = cloudfront_client.get_distribution(Id=dist_id)
        deployment_status = dist_details['Distribution']['Status']
            
        if deployment_status == 'Deployed':
            success("CloudFront distribution is fully deployed")
            return dist_id
            
        # Show progress every 30 seconds
        if attempts % 15 == 0:  # 15 attempts = 30 seconds (15 * 2 seconds)
            print(f"    Still deploying... (attempt {attempts + 1}/{max_attempts})")
            
        attempts += 1
        time.sleep(2)  # Wait 2 seconds between checks
        
    failure("CloudFront distribution deployment timed out after 10 minutes")

    return dist_id

def cloudfront_logging(session: boto3.Session, log_bucket: str, dist_id: str) -> None:
    """Enable CloudFront logging to S3 bucket.
    
    Args:
        session: AWS boto3 session
        log_bucket: Name of the S3 bucket for logs
        dist_id: CloudFront distribution ID
    """
    cloudwatch_client = session.client('logs')
    
    account_id = session.client('sts').get_caller_identity()['Account']
    
    try:
        for delivery in cloudwatch_client.describe_deliveries()['deliveries']:
            if delivery['deliverySourceName'] == f'SCRAM-cloudfront-{dist_id}':
                success(f"CloudFront logging enabled for distribution {dist_id}")
                return

    except Exception as e:
        progress(f"    Error: {str(e)}")
        pass

    try:
        # Create a delivery source for CloudFront logs
        response = cloudwatch_client.put_delivery_source(
            name=f'SCRAM-cloudfront-{dist_id}',
            resourceArn=f'arn:aws:cloudfront::{account_id}:distribution/{dist_id}',
            logType='ACCESS_LOGS'
        )
        
        # Create a delivery destination for the S3 bucket
        account_id = session.client('sts').get_caller_identity()['Account']

        progress(f"log delivery source {dist_id}")

        destination =cloudwatch_client.put_delivery_destination(
            name=f'SCRAM-cloudfront-{dist_id}-s3',
            outputFormat='w3c',
            deliveryDestinationConfiguration={
                'destinationResourceArn': f'arn:aws:s3:::{log_bucket}'
            }
        )

        destination_arn = destination['deliveryDestination']['arn']

        # Link the source to the destination
        cloudwatch_client.create_delivery(
            deliverySourceName=f'SCRAM-cloudfront-{dist_id}',
            deliveryDestinationArn=destination_arn
        )
        
        success(f"CloudFront logging enabled for distribution {dist_id}")
        
    except Exception as e:
        failure("CloudFront logging configuration")
        progress(f"    Error: {str(e)}")

def cloudfront_domain(session: boto3.Session, dist_id: str) -> Optional[str]:
    """Get the target domain for a CloudFront distribution.
    
    Args:
        session: AWS boto3 session
        dist_id: CloudFront distribution ID
        
    Returns:
        The distribution's domain name if found, None otherwise
    """
    cloudfront_client = session.client('cloudfront')
    
    try:
        response = cloudfront_client.get_distribution(Id=dist_id)
        domain = response['Distribution']['DomainName']
        success(f"CloudFront distribution domain for {dist_id}")
        return domain
    except Exception as e:
        failure(f"CloudFront distribution domain for {dist_id}")
        progress(f"    Error: {str(e)}")
        return None 

def route53_aliases(session: boto3.Session, hosted_zones: Dict[str, Dict], domains_to_parents: Dict[str, str], dist_id: str) -> None:
    """Create Route 53 aliases for the domains.
    
    Args:
        session: AWS boto3 session
        hosted_zones: Dictionary of hosted zones
        domains_to_parents: Dictionary mapping domains to their parent domains
        dist_id: CloudFront distribution ID
    """
    route53_client = session.client('route53')
    
    # Get the CloudFront distribution domain
    target_domain = cloudfront_domain(session, dist_id)
    if not target_domain:
        failure("Failed to get CloudFront distribution domain")
        return

    for domain in domains_to_parents.keys():
        hosted_zone_id = hosted_zones[domains_to_parents[domain]]['Id']

        # create route53 aliases for the domain
        response = route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': domain,
                            'Type': 'A',
                            'AliasTarget': {
                                'HostedZoneId': 'Z2FDTNDATAQYW2',
                                'DNSName': target_domain,
                                'EvaluateTargetHealth': False     
                            }
                        }
                    },
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': domain,
                            'Type': 'AAAA',
                            'AliasTarget': {
                                'HostedZoneId': 'Z2FDTNDATAQYW2',
                                'DNSName': target_domain,
                                'EvaluateTargetHealth': False     
                            }
                        }
                    }
                ]
            }
        )

        success(f"Route53 aliases created for {domain}")

def calculate_file_checksum(file_path: pathlib.Path) -> str:
    """Calculate SHA256 checksum of a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        SHA256 checksum as a hex string
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read the file in chunks to handle large files
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def build_local_checksum_map(directory: pathlib.Path) -> Dict[str, str]:
    """Recursively build a map of file paths to their SHA256 checksums.
    
    Args:
        directory: Root directory to scan
        
    Returns:
        Dictionary mapping file paths to their checksums
    """
    checksum_map = {}
    
    def process_directory(current_dir: pathlib.Path):
        for item in current_dir.iterdir():
            if item.is_file():
                # Skip .git directory and its contents
                if '.git' in str(item):
                    continue
                relative_path = str(item.relative_to(directory))
                checksum = calculate_file_checksum(item)
                checksum_map[relative_path] = checksum
            elif item.is_dir():
                process_directory(item)
    
    process_directory(directory)
    return checksum_map

def get_s3_checksums(s3_client, bucket: str) -> Dict[str, str]:
    """Get SHA256 checksums of all files in S3 bucket.
    
    Args:
        s3_client: AWS S3 client
        bucket: Name of the S3 bucket
        
    Returns:
        Dictionary mapping file paths to their checksums
    """
    checksum_map = {}
    paginator = s3_client.get_paginator('list_objects_v2')
    
    for page in paginator.paginate(Bucket=bucket):
        if 'Contents' in page:
            for obj in page['Contents']:
                key = obj['Key']
                # Get the object's metadata to find the SHA256 checksum
                try:
                    response = s3_client.head_object(Bucket=bucket, Key=key)
                    checksum = response.get('Metadata', {}).get('sha256', '')
                    if checksum:
                        checksum_map[key] = checksum
                except Exception as e:
                    progress(f"    Error getting checksum for {key}: {str(e)}")
    
    return checksum_map

def s3_sync(session: boto3.Session, bucket: str) -> Set[str]:
    """Synchronize local files with S3 bucket using checksums.
    
    Args:
        session: AWS boto3 session
        bucket: Name of the S3 bucket
        
    Returns:
        Set of file paths that were uploaded
    """
    s3_client = session.client('s3')
    
    # Content type mapping
    content_types = {
        '.html': 'text/html',
        '.css': 'text/css',
        '.js': 'application/javascript',
        '.json': 'application/json',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.svg': 'image/svg+xml',
        '.txt': 'text/plain',
        '.xml': 'application/xml'
    }
    
    try:
        # Get current working directory
        cwd = pathlib.Path.cwd()
        
        # Build local checksum map
        progress("Building local file checksums")
        local_checksums = build_local_checksum_map(cwd)
        
        # Get S3 checksums
        progress("Getting S3 file checksums")
        s3_checksums = get_s3_checksums(s3_client, bucket)
        
        # Find files that need to be uploaded
        files_to_upload = set()
        for local_path, local_checksum in local_checksums.items():
            s3_checksum = s3_checksums.get(local_path)
            if s3_checksum != local_checksum:
                files_to_upload.add(local_path)
        
        # Add files that exist locally but not in S3
        files_to_upload.update(set(local_checksums.keys()) - set(s3_checksums.keys()))
        
        if not files_to_upload:
            success("All files are in sync with S3")
            return set()
        
        # Upload files that need updating
        for file_path in files_to_upload:
            full_path = cwd / file_path
            content_type = content_types.get(full_path.suffix.lower(), 'binary/octet-stream')
            
            try:
                checksum = local_checksums[file_path]
                # Upload with checksum in metadata
                s3_client.upload_file(
                    str(full_path),
                    bucket,
                    file_path,
                    ExtraArgs={
                        'ContentType': content_type,
                        'CacheControl': 'max-age=3600',  # Cache for 1 hour
                        'Metadata': {
                            'sha256': checksum
                        }
                    }
                )
                success(f"S3 Upload {file_path}")
            except Exception as e:
                failure(f"S3 Upload {file_path}")
                progress(f"    Error: {str(e)}")
        
        success("S3 Sync Complete")
        
        return files_to_upload

    except Exception as e:
        failure("S3 Sync")
        progress(f"    Error: {str(e)}")
        return set()

def cloudfront_invalidation(session: boto3.Session, dist_id: str, paths: Set[str]) -> None:
    """Create a CloudFront invalidation for the specified paths.
    
    Args:
        session: AWS boto3 session
        dist_id: CloudFront distribution ID
        paths: Set of paths to invalidate
    """
    if not paths:
        progress("No files to invalidate")
        return

    if '/index.html' in paths:
        paths.add('/')

    # Sanitize paths by replacing invalid characters with *
    sanitized_paths = set()
    for path in paths:
        # Find the first invalid character
        for i, char in enumerate(path):
            if not (char.isalnum() or char in '-_/'):
                # Truncate at the first invalid character and add *
                sanitized_path = path[:i] + '*'
                sanitized_paths.add(sanitized_path)
                break
        else:
            # If no invalid characters found, use the original path
            sanitized_paths.add(path)
    
    cloudfront_client = session.client('cloudfront')
    
    try:
        progress(f'Invalidating {len(sanitized_paths)} paths')
        progress([f'/{path}' for path in sanitized_paths])
        # Create the invalidation
        response = cloudfront_client.create_invalidation(
            DistributionId=dist_id,
            InvalidationBatch={
                'Paths': {
                    'Quantity': len(sanitized_paths),
                    'Items': [f'/{path}' for path in sanitized_paths]
                },
                'CallerReference': str(uuid.uuid4())
            }
        )
        
        invalidation_id = response['Invalidation']['Id']
        success(f"CloudFront invalidation created: {invalidation_id}")
        
        # Wait for the invalidation to complete
        print("\nWaiting for CloudFront invalidation to complete...")
        max_attempts = 300  # 10 minutes maximum
        attempts = 0
        
        while attempts < max_attempts:
            invalidation = cloudfront_client.get_invalidation(
                DistributionId=dist_id,
                Id=invalidation_id
            )
            invalidation_status = invalidation['Invalidation']['Status']
            
            if invalidation_status == 'Completed':
                success("CloudFront invalidation completed")
                return
            
            # Show progress every 30 seconds
            if attempts % 15 == 0:  # 15 attempts = 30 seconds (15 * 2 seconds)
                progress(f"    Still invalidating... (attempt {attempts + 1}/{max_attempts})")
            
            attempts += 1
            time.sleep(2)  # Wait 2 seconds between checks
        
        failure("CloudFront invalidation timed out")
        
    except Exception as e:
        failure("CloudFront invalidation")
        progress(f"    Error: {str(e)}")

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Manage AWS infrastructure for static websites')
    parser.add_argument('--register', action='store_true', help='Register new domains')
    parser.add_argument('--setup', action='store_true', help='Set up AWS infrastructure')
    parser.add_argument('domains', nargs='*', help='Additional domains')

    try:
        args = parser.parse_args()
    except Exception as e:
        usage()
        sys.exit(1)
    
    # Our working directory is always our main site name
    domains = [pathlib.Path.cwd().name.lower()]
    
    # Add command line domains
    domains += args.domains
    
    # And anything in an 'aliases' file
    try:
        domains += map(str.strip, open("aliases").readlines())
    except:
        pass
    
    # Normalize everything to lowercase
    domains = list(map(str.lower, domains))
    
    # Create a boto3 session
    session = boto3.Session()   # Filter out subdomains of domains that are already in the list
    
    # Sort by length (shortest first) to ensure we check parent domains first
    domains.sort(key=len)
    parent_domains = []
    domains_to_parents = {}
    
    for domain in domains:

        domains_to_parents[domain] = domain
        # Check if this domain is a subdomain of any domain already in unique_domains
        is_subdomain = False
        for parent in parent_domains:
            if domain.endswith('.' + parent):
                is_subdomain = True
                domains_to_parents[domain] = parent
                break

        if not is_subdomain:
            parent_domains.append(domain)

    bucket = domains[0]

    if args.register:
        # Register domains
        route53_register(session, parent_domains)
    
    if args.setup:
        # Check if we have these domains registered
        hosted_zones = route53_zones(session, parent_domains)
        
        # Check if we have a certificate with all of these names on it
        cert_arn = acm(session, parent_domains, hosted_zones)

        log_bucket = "scram-" + ''.join(c for c in bucket if c.isalnum() or c == '-')
        
        # Make sure an S3 bucket exists
        s3_buckets(session, bucket, log_bucket)

        # Now create a cloudfront distribution
        dist_id = cloudfront(session, domains, cert_arn)

        # S3 permissions
        s3_policy(session, bucket, log_bucket, dist_id)
        
        # Enable CloudFront logging
        cloudfront_logging(session, log_bucket, dist_id)

        route53_aliases(session, hosted_zones, domains_to_parents, dist_id)
        
    # At long last, sync the files to S3
    uploaded = s3_sync(session, bucket)

    dist_id = cloudfront_distribution(session, domains)

    # Create a CloudFront invalidation
    cloudfront_invalidation(session, dist_id, uploaded)
