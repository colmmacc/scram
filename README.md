# SCRAM - S3, CloudFront, Route53, and ACM

A command-line tool for managing static website hosting on AWS, including domain registration, SSL certificates, S3 buckets, and CloudFront distributions.

## Features

- Domain registration with WHOIS privacy
- Route 53 DNS management
- ACM SSL certificate management
- S3 bucket creation and configuration
- CloudFront distribution setup
- Automatic file synchronization to S3
- Automatic CloudFront invalidations

## Prerequisites

- Python 3.6 or later
- AWS CLI configured with appropriate credentials
- Required Python packages:
  - boto3
  - termcolor

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/scram.git
   cd scram
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

scram operates in two modes: domain registration and infrastructure setup.

### Domain Registration

To register new domains:

```bash
mkdir example.com
cd example.com
scram.py --register www.example.com blog.example.com
```

This will:
- Check domain availability
- Register available domains
- Enable WHOIS privacy
- Use contact details from your most recent domain registration

### Infrastructure Setup

To set up AWS infrastructure for existing domains:

```bash
mkdir example.com
cd example.com
scram.py --setup www.example.com blog.example.com
```

This will:
- Create Route 53 hosted zones
- Request ACM certificates
- Set up S3 buckets
- Configure CloudFront distributions
- Set appropriate permissions
- Sync your files to S3

### Additional Domains

Additional domains can be specified in two ways:
1. As command line arguments
2. In an 'aliases' file in the current directory

Example aliases file:
```
www.example.com
blog.example.com
```

## Configuration

### AWS Credentials

Ensure your AWS credentials are properly configured in one of these ways:
- AWS CLI configuration
- Environment variables
- IAM role

### Contact Information

When registering new domains, scram will:
1. Try to reuse contact details from your most recent domain registration
2. Prompt you to confirm or provide new contact details

## License

Copyright 2025 Colm MacCárthaigh

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
