# SCRAM - Static Content Route53 ACM Manager

A tool for managing AWS infrastructure for hosting static websites.

## Features

- Domain registration and management with Route 53
- SSL/TLS certificate management with ACM
- S3 bucket creation and configuration
- CloudFront distribution setup
- File synchronization with checksum verification
- CloudFront cache invalidation
- Progress and status reporting

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

### Basic Setup

1. Create a directory for your website:
   ```bash
   mkdir example.com
   cd example.com
   ```

2. Run SCRAM to set up the infrastructure:
   ```bash
   python ../scram/scram.py --setup
   ```

### Domain Registration

To register new domains:
   ```bash
   python ../scram/scram.py --register www.example.com blog.example.com
   ```

### File Synchronization

SCRAM will automatically:
- Calculate checksums for local files
- Compare with files in S3
- Upload only changed or new files
- Create CloudFront invalidations for updated files

## Status Reporting

SCRAM provides clear status reporting with color-coded output:
- Success messages in green
- Failure messages in red
- Progress messages in yellow

## Requirements

- Python 3.6+
- AWS credentials configured
- Required Python packages:
  - boto3
  - termcolor

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
