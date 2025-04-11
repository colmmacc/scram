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

import termcolor
import argparse
import pathlib
import boto3
import json
import time
import sys
import os

def usage():
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

# Print a colorful status message
def status(message, status):
    message = termcolor.colored(message, 'cyan')
    status  = termcolor.colored('pass', 'green')
    if status:
        termcolor.colored('fail','red')
    print(f"{message:50s} ...  [ {status:s} ]")

# Register domains with Route 53
def route53_register(session, domains):
    route53_client = session.client('route53domains')
    
    # List existing domains
    try:
        existing_domains = route53_client.list_domains()
        if existing_domains['Domains']:
            print("\nYour existing domains:")
            for domain in existing_domains['Domains']:
                print(f"    - {domain['DomainName']}")
            print()
            
            # Get contact details from the most recent domain
            most_recent = existing_domains['Domains'][0]
            contact_details = route53_client.get_contact_reachability_status(
                DomainName=most_recent['DomainName']
            )
            contact_info = contact_details['ContactReachabilityInfo']
            
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
                
                status(f"Domain registration {domain}", True)
                print(f"    Operation ID: {response['OperationId']}")
                print("    Note: Domain registration can take up to 3 days to complete.")
                
            elif availability['Availability'] == 'UNAVAILABLE':
                status(f"Domain registration {domain}", False)
                print(f"    Error: Domain {domain} is not available for registration")
            else:
                status(f"Domain registration {domain}", False)
                print(f"    Error: Domain {domain} availability check failed: {availability['Availability']}")
                
        except Exception as e:
            status(f"Domain registration {domain}", False)
            print(f"    Error: {str(e)}")

# Check for hosted zones in Route 53
def route53_zones(session, domains):
    route53_client = session.client('route53')
    
    for domain in domains:
        try:
            # List all hosted zones
            response = route53_client.list_hosted_zones()
            
            # Check if domain has a hosted zone
            domain_found = False
            for zone in response['HostedZones']:
                # Remove trailing dot from zone name for comparison
                zone_name = zone['Name'].rstrip('.')
                if zone_name == domain:
                    domain_found = True
                    status(f"Route53 zone {domain}", True)
                    print(f"    Zone ID: {zone['Id']}")
                    break
            
            if not domain_found:
                status(f"Route53 zone {domain}", False)
                print(f"    Warning: No hosted zone found for domain: {domain}")
                
        except Exception as e:
            status(f"Route53 zone {domain}", False)
            print(f"    Error: {str(e)}")

# Create an ACM certificate for all of the domains
def acm(session, domains):
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
        status("ACM Certificate found", True)
        print(f"    Certificate ARN: {matching_cert['CertificateArn']}")
        return matching_cert['CertificateArn']
    
    # If no matching certificate found, create a new one
    try:
        response = acm_client.request_certificate(
            DomainName=domains[0],
            SubjectAlternativeNames=domains[1:],
            ValidationMethod='DNS'
        )
        
        cert_arn = response['CertificateArn']
        status("ACM Certificate requested", True)
        print(f"    Certificate ARN: {cert_arn}")
        
        # Get the validation options
        cert_details = acm_client.describe_certificate(CertificateArn=cert_arn)
        validation_options = cert_details['Certificate']['DomainValidationOptions']
        
        # Print the DNS records needed for validation
        print("\nDNS validation records needed:")
        for option in validation_options:
            domain = option['DomainName']
            record = option['ResourceRecord']
            print(f"    {domain}:")
            print(f"        Name: {record['Name']}")
            print(f"        Type: {record['Type']}")
            print(f"        Value: {record['Value']}")
            print()
        
        return cert_arn
        
    except Exception as e:
        status("ACM Certificate request", False)
        print(f"    Error: {str(e)}")
        return None

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
def cloudfront(session, domains, cert_arn=None):
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
        status("CloudFront Distribution found", True)
        print(f"    Distribution ID: {matching_dist['Id']}")
        print(f"    Domain: {matching_dist['DomainName']}")
        return matching_dist['Id']
    
    # If no matching distribution found, create a new one
    try:
        # Get the S3 bucket name (first domain)
        s3_bucket = domains[0]
        
        # Create distribution configuration
        distribution_config = {
            'CallerReference': str(int(time.time())),  # Unique string
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
                'MinTTL': 0
            },
            'CacheBehaviors': {'Quantity': 0},
            'CustomErrorResponses': {'Quantity': 0},
            'Comment': f'Distribution for {", ".join(domains)}',
            'Enabled': True,
            'PriceClass': 'PriceClass_100',  # US, Canada, Europe
        }
        
        # Add SSL configuration if certificate is provided
        if cert_arn:
            distribution_config['ViewerCertificate'] = {
                'ACMCertificateArn': cert_arn,
                'SSLSupportMethod': 'sni-only',
                'MinimumProtocolVersion': 'TLSv1.2_2021'
            }
        
        # Create the distribution
        response = cloudfront_client.create_distribution(
            DistributionConfig=distribution_config
        )
        
        dist_id = response['Distribution']['Id']
        status("CloudFront Distribution created", True)
        print(f"    Distribution ID: {dist_id}")
        print(f"    Domain: {response['Distribution']['DomainName']}")
        print("\nNote: Distribution creation can take 15-20 minutes to complete.")
        
        return dist_id
        
    except Exception as e:
        status("CloudFront Distribution creation", False)
        print(f"    Error: {str(e)}")
        return None

# S3 permissions
def s3_perms(session, domains):
    s3_client = session.client('s3')
    
    for domain in domains:
        try:
            # Add permission for CloudFront to access the bucket
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowCloudFrontServicePrincipalReadOnly",
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "cloudfront.amazonaws.com"
                        },
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{domain}/*",
                        "Condition": {
                            "StringEquals": {
                                "AWS:SourceArn": f"arn:aws:cloudfront::*:distribution/*"
                            }
                        }
                    }
                ]
            }
            s3_client.put_bucket_policy(
                Bucket = domain,
                Policy = json.dumps(policy)
            )
            
            status("S3 Bucket " + domain, True)
        except Exception as e:
            status("S3 Bucket " + domain, False)
            print(f"    Error: {str(e)}")

# Synchronize files with S3 bucket
def s3_sync(session, domains):
    s3_client = session.client('s3')
    bucket = domains[0]  # Use the primary domain as the bucket name
    
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
        # Get the current working directory
        cwd = pathlib.Path.cwd()
        
        # Walk through all files in the directory
        for file_path in cwd.rglob('*'):
            if file_path.is_file():
                # Calculate the S3 key (path relative to cwd)
                relative_path = file_path.relative_to(cwd)
                s3_key = str(relative_path)
                
                # Skip .git directory and its contents
                if '.git' in s3_key:
                    continue
                
                # Determine content type based on file extension
                content_type = content_types.get(file_path.suffix.lower(), 'binary/octet-stream')
                
                # Upload the file
                try:
                    s3_client.upload_file(
                        str(file_path),
                        bucket,
                        s3_key,
                        ExtraArgs={
                            'ContentType': content_type,
                            'CacheControl': 'max-age=3600'  # Cache for 1 hour
                        }
                    )
                    status(f"S3 Upload {s3_key}", True)
                except Exception as e:
                    status(f"S3 Upload {s3_key}", False)
                    print(f"    Error: {str(e)}")
        
        status("S3 Sync Complete", True)
        
    except Exception as e:
        status("S3 Sync", False)
        print(f"    Error: {str(e)}")

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Manage AWS infrastructure for static websites')
    parser.add_argument('--register', action='store_true', help='Register new domains')
    parser.add_argument('--setup', action='store_true', help='Set up AWS infrastructure')
    parser.add_argument('domains', nargs='*', help='Additional domains')
    args = parser.parse_args()
    
    if not (args.register or args.setup):
        usage()
        sys.exit(1)
    
    # Our working directory is always our main site name
    domains = [ pathlib.Path.cwd().name.lower() ]
    
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
    session = boto3.Session()
    
    if args.register:
        # Register domains
        route53_register(session, domains)
    
    if args.setup:
        # Check if we have these domains registered
        route53_zones(session, domains)
        
        # Check if we have a certificate with all of these names on it
        cert_arn = acm(session, domains)
        
        # Create the route53 verification records
        route53_verify(session, domains)
        
        # Confirm that the certificate has been verified
        acm_verify(session)
        
        # Make sure an S3 bucket exists
        s3(session, domains)
        
        # S3 logging bucket
        s3_log(session, domains)
        
        # Now create a cloudfront distribution
        cloudfront(session, domains, cert_arn)
        
        # S3 permissions
        s3_perms(session, domains)
        
    # At long last, sync the files to S3
    s3_sync(session, domains)

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
