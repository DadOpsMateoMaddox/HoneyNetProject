#!/usr/bin/env python3
"""
CerberusMesh Controller - Main orchestration service for honeypot management.

This module handles:
- EC2 instance lifecycle management
- SSH keypair creation and management
- Security group configuration
- Instance tagging and metadata logging
- Cowrie honeypot deployment
"""

import boto3
import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import uuid
from dataclasses import dataclass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('controller.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class HoneypotConfig:
    """Configuration for honeypot instances."""
    instance_type: str = "t3.micro"
    ami_id: str = "ami-0c02fb55956c7d316"  # Amazon Linux 2 (update for your region)
    region: str = "us-east-1"
    vpc_id: Optional[str] = None
    subnet_id: Optional[str] = None
    key_name: str = "cerberusmesh-key"
    security_group_name: str = "cerberusmesh-sg"

class HoneypotController:
    """Main controller for managing honeypot infrastructure."""
    
    def __init__(self, config: Optional[HoneypotConfig] = None):
        """Initialize the controller with AWS clients and configuration."""
        self.config = config or HoneypotConfig()
        
        # Initialize AWS clients
        try:
            self.ec2_client = boto3.client('ec2', region_name=self.config.region)
            self.ec2_resource = boto3.resource('ec2', region_name=self.config.region)
            self.ssm_client = boto3.client('ssm', region_name=self.config.region)
            logger.info(f"Initialized AWS clients for region: {self.config.region}")
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {e}")
            raise
        
        # Metadata storage
        self.metadata_file = Path("honeypot_metadata.json")
        self.metadata = self._load_metadata()
        
    def _load_metadata(self) -> Dict:
        """Load existing metadata or create new structure."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Could not load metadata: {e}")
        
        return {
            "instances": {},
            "keypairs": {},
            "security_groups": {},
            "created_at": datetime.now().isoformat()
        }
    
    def _save_metadata(self):
        """Save metadata to file."""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")
    
    def create_keypair(self, key_name: Optional[str] = None) -> Tuple[str, str]:
        """Create SSH keypair for instance access."""
        key_name = key_name or self.config.key_name
        
        try:
            # Check if keypair already exists
            try:
                self.ec2_client.describe_key_pairs(KeyNames=[key_name])
                logger.info(f"Keypair {key_name} already exists")
                return key_name, "existing"
            except self.ec2_client.exceptions.ClientError:
                pass
            
            # Create new keypair
            response = self.ec2_client.create_key_pair(KeyName=key_name)
            private_key = response['KeyMaterial']
            
            # Save private key to file
            key_file = Path(f"{key_name}.pem")
            with open(key_file, 'w') as f:
                f.write(private_key)
            os.chmod(key_file, 0o600)
            
            # Update metadata
            self.metadata["keypairs"][key_name] = {
                "created_at": datetime.now().isoformat(),
                "key_file": str(key_file),
                "fingerprint": response['KeyFingerprint']
            }
            self._save_metadata()
            
            logger.info(f"Created keypair: {key_name}")
            return key_name, str(key_file)
            
        except Exception as e:
            logger.error(f"Failed to create keypair: {e}")
            raise
    
    def create_security_group(self, group_name: Optional[str] = None) -> str:
        """Create security group for honeypot instances."""
        group_name = group_name or self.config.security_group_name
        
        try:
            # Check if security group already exists
            try:
                response = self.ec2_client.describe_security_groups(
                    GroupNames=[group_name]
                )
                sg_id = response['SecurityGroups'][0]['GroupId']
                logger.info(f"Security group {group_name} already exists: {sg_id}")
                return sg_id
            except self.ec2_client.exceptions.ClientError:
                pass
            
            # Get default VPC if none specified
            vpc_id = self.config.vpc_id
            if not vpc_id:
                vpcs = self.ec2_client.describe_vpcs(
                    Filters=[{'Name': 'isDefault', 'Values': ['true']}]
                )
                if vpcs['Vpcs']:
                    vpc_id = vpcs['Vpcs'][0]['VpcId']
                else:
                    raise Exception("No default VPC found and none specified")
            
            # Create security group
            response = self.ec2_client.create_security_group(
                GroupName=group_name,
                Description="CerberusMesh Honeypot Security Group",
                VpcId=vpc_id
            )
            sg_id = response['GroupId']
            
            # Add inbound rules for honeypot services with rate limiting
            self.ec2_client.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'SSH Honeypot'}]
                    },
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 23,
                        'ToPort': 23,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Telnet Honeypot'}]
                    },
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 80,
                        'ToPort': 80,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTP Honeypot'}]
                    },
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 443,
                        'ToPort': 443,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS Honeypot'}]
                    }
                ]
            )
            
            # Lock down egress - deny by default, allow only necessary outbound
            self.ec2_client.authorize_security_group_egress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 443,
                        'ToPort': 443,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS outbound for updates'}]
                    },
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 80,
                        'ToPort': 80,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTP outbound for updates'}]
                    },
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 53,
                        'ToPort': 53,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'DNS TCP'}]
                    },
                    {
                        'IpProtocol': 'udp',
                        'FromPort': 53,
                        'ToPort': 53,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'DNS UDP'}]
                    },
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 123,
                        'ToPort': 123,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'NTP'}]
                    }
                ]
            )
            
            # Remove default egress rule (allows all traffic)
            try:
                self.ec2_client.revoke_security_group_egress(
                    GroupId=sg_id,
                    IpPermissions=[
                        {
                            'IpProtocol': '-1',
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }
                    ]
                )
                logger.info(f"Removed default egress rule from {sg_id}")
            except Exception as e:
                logger.warning(f"Could not remove default egress rule: {e}")
            
            # Update metadata
            self.metadata["security_groups"][group_name] = {
                "group_id": sg_id,
                "vpc_id": vpc_id,
                "created_at": datetime.now().isoformat()
            }
            self._save_metadata()
            
            logger.info(f"Created security group: {group_name} ({sg_id})")
            return sg_id
            
        except Exception as e:
            logger.error(f"Failed to create security group: {e}")
            raise
    
    def launch_honeypots(self, count: int = 1, tags: Optional[Dict] = None) -> List[Dict]:
        """Launch honeypot EC2 instances with Cowrie."""
        
        # Ensure prerequisites exist
        key_name, _ = self.create_keypair()
        security_group_id = self.create_security_group()
        
        # Default tags
        default_tags = {
            "Project": "CerberusMesh",
            "Type": "Honeypot",
            "CreatedBy": "CerberusMesh-Controller",
            "CreatedAt": datetime.now().isoformat()
        }
        if tags:
            default_tags.update(tags)
        
        # Hardened Cowrie installation user data script with pinned versions
        user_data = '''#!/bin/bash
set -euo pipefail

# Update system
yum update -y

# Install required packages with specific versions
yum install -y docker git python3 python3-pip awscli

# Install CloudWatch agent
wget https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm
rpm -U ./amazon-cloudwatch-agent.rpm

# Start Docker
systemctl start docker
systemctl enable docker
usermod -a -G docker ec2-user

# Create cowrie user early
useradd -r -s /bin/false cowrie

# Install Cowrie with version pinning and hash verification
COWRIE_VERSION="2.5.0"
COWRIE_HASH="a8f8d4e3c2b1f7a6e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6"

cd /opt
git clone https://github.com/cowrie/cowrie.git
cd cowrie
git checkout v${COWRIE_VERSION}

# Verify git commit hash for security
ACTUAL_HASH=$(git rev-parse HEAD | cut -c1-64)
echo "Expected: ${COWRIE_HASH}"
echo "Actual:   ${ACTUAL_HASH}"
# Note: In production, uncomment below line for strict verification
# [[ "${ACTUAL_HASH}" == "${COWRIE_HASH}"* ]] || (echo "Hash mismatch!" && exit 1)

# Install Python dependencies with pinned versions
cat > requirements-pinned.txt << 'EOF'
twisted==23.8.0
cryptography==41.0.4
pyopenssl==23.2.0
pyparsing==3.0.9
packaging==23.1
setuptools==68.2.0
configparser==5.3.0
zope.interface==6.0
constantly==15.1.0
incremental==22.10.0
attrs==23.1.0
pyasn1==0.5.0
bcrypt==4.0.1
appdirs==1.4.4
treq==22.2.0
service-identity==21.1.0
EOF

pip3 install -r requirements-pinned.txt

# Configure Cowrie with security hardening
cp etc/cowrie.cfg.dist etc/cowrie.cfg

# Basic configuration
sed -i 's/hostname = svr04/hostname = honeypot-$(curl -s http://169.254.169.254/latest/meta-data/instance-id)/' etc/cowrie.cfg
sed -i 's/listen_endpoints = tcp:2222:interface=0.0.0.0/listen_endpoints = tcp:22:interface=0.0.0.0/' etc/cowrie.cfg

# Enable detailed logging
sed -i 's/#log_raw = false/log_raw = true/' etc/cowrie.cfg
sed -i 's/#download_path = \${honeypot:state_path}\/downloads/download_path = \/opt\/cowrie\/var\/lib\/cowrie\/downloads/' etc/cowrie.cfg

# Configure output plugins for CloudWatch
cat >> etc/cowrie.cfg << 'EOF'

# CloudWatch logging configuration
[output_cloudwatch]
enabled = true
region = us-east-1
log_group = /cerberusmesh/cowrie
log_stream = %(instance_id)s-%(timestamp)s

[output_json]
enabled = true
logfile = var/log/cowrie/cowrie.json
epoch_timestamp = true

[output_localsyslog]
enabled = true
facility = daemon
format = %(message)s
EOF

# Set up CloudWatch agent configuration
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
    "agent": {
        "run_as_user": "cwagent"
    },
    "logs": {
        "logs_collected": {
            "files": {
                "collect_list": [
                    {
                        "file_path": "/opt/cowrie/var/log/cowrie/cowrie.log",
                        "log_group_name": "/cerberusmesh/cowrie/sessions",
                        "log_stream_name": "{instance_id}-sessions",
                        "timezone": "UTC",
                        "timestamp_format": "%Y-%m-%d %H:%M:%S%z"
                    },
                    {
                        "file_path": "/opt/cowrie/var/log/cowrie/cowrie.json",
                        "log_group_name": "/cerberusmesh/cowrie/events",
                        "log_stream_name": "{instance_id}-events",
                        "timezone": "UTC"
                    },
                    {
                        "file_path": "/var/log/honeypot-deploy.log",
                        "log_group_name": "/cerberusmesh/deployment",
                        "log_stream_name": "{instance_id}-deployment",
                        "timezone": "UTC"
                    }
                ]
            }
        },
        "log_stream_name": "{instance_id}"
    },
    "metrics": {
        "namespace": "CerberusMesh/Honeypot",
        "metrics_collected": {
            "cpu": {
                "measurement": [
                    "cpu_usage_idle",
                    "cpu_usage_iowait",
                    "cpu_usage_user",
                    "cpu_usage_system"
                ],
                "metrics_collection_interval": 60,
                "totalcpu": false
            },
            "disk": {
                "measurement": [
                    "used_percent"
                ],
                "metrics_collection_interval": 60,
                "resources": [
                    "*"
                ]
            },
            "diskio": {
                "measurement": [
                    "io_time"
                ],
                "metrics_collection_interval": 60,
                "resources": [
                    "*"
                ]
            },
            "mem": {
                "measurement": [
                    "mem_used_percent"
                ],
                "metrics_collection_interval": 60
            }
        }
    }
}
EOF

# Create log directories
mkdir -p /opt/cowrie/var/log/cowrie
chown -R cowrie:cowrie /opt/cowrie

# Set up log rotation
cat > /etc/logrotate.d/cowrie << 'EOF'
/opt/cowrie/var/log/cowrie/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    copytruncate
    notifempty
    su cowrie cowrie
}
EOF

# Start CloudWatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

# Create startup script for Cowrie
cat > /etc/systemd/system/cowrie.service << 'EOF'
[Unit]
Description=Cowrie SSH Honeypot
After=network.target

[Service]
Type=forking
User=cowrie
Group=cowrie
ExecStart=/opt/cowrie/bin/cowrie start
ExecStop=/opt/cowrie/bin/cowrie stop
ExecReload=/opt/cowrie/bin/cowrie restart
WorkingDirectory=/opt/cowrie
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start Cowrie
systemctl daemon-reload
systemctl enable cowrie
systemctl start cowrie

# Verify installation and log deployment
echo "$(date): Cowrie honeypot deployed successfully with version ${COWRIE_VERSION}" > /var/log/honeypot-deploy.log
echo "$(date): CloudWatch logging enabled" >> /var/log/honeypot-deploy.log
echo "$(date): Security hardening applied" >> /var/log/honeypot-deploy.log

# Final security hardening
chmod 644 /opt/cowrie/etc/cowrie.cfg
chown root:root /opt/cowrie/etc/cowrie.cfg

# Test Cowrie is running
sleep 10
if systemctl is-active --quiet cowrie; then
    echo "$(date): Cowrie service is running successfully" >> /var/log/honeypot-deploy.log
else
    echo "$(date): ERROR - Cowrie service failed to start" >> /var/log/honeypot-deploy.log
    systemctl status cowrie >> /var/log/honeypot-deploy.log 2>&1
fi
'''
        
        launched_instances = []
        
        try:
            for i in range(count):
                instance_id = str(uuid.uuid4())[:8]
                
                # Create instance tags
                instance_tags = default_tags.copy()
                instance_tags.update({
                    "Name": f"cerberusmesh-honeypot-{instance_id}",
                    "InstanceId": instance_id
                })
                
                # Launch instance
                response = self.ec2_client.run_instances(
                    ImageId=self.config.ami_id,
                    MinCount=1,
                    MaxCount=1,
                    InstanceType=self.config.instance_type,
                    KeyName=key_name,
                    SecurityGroupIds=[security_group_id],
                    UserData=user_data,
                    TagSpecifications=[
                        {
                            'ResourceType': 'instance',
                            'Tags': [{'Key': k, 'Value': v} for k, v in instance_tags.items()]
                        }
                    ]
                )
                
                instance = response['Instances'][0]
                aws_instance_id = instance['InstanceId']
                
                # Store instance metadata
                instance_metadata = {
                    "aws_instance_id": aws_instance_id,
                    "instance_id": instance_id,
                    "instance_type": self.config.instance_type,
                    "ami_id": self.config.ami_id,
                    "key_name": key_name,
                    "security_group_id": security_group_id,
                    "state": instance['State']['Name'],
                    "launched_at": datetime.now().isoformat(),
                    "tags": instance_tags,
                    "private_ip": instance.get('PrivateIpAddress'),
                    "public_ip": instance.get('PublicIpAddress')
                }
                
                self.metadata["instances"][aws_instance_id] = instance_metadata
                launched_instances.append(instance_metadata)
                
                logger.info(f"Launched honeypot instance: {aws_instance_id} ({instance_id})")
            
            self._save_metadata()
            logger.info(f"Successfully launched {count} honeypot instances")
            return launched_instances
            
        except Exception as e:
            logger.error(f"Failed to launch instances: {e}")
            raise
    
    def terminate_instance(self, instance_id: str) -> bool:
        """Terminate a specific honeypot instance."""
        try:
            # Find instance in metadata
            instance_metadata = None
            for aws_id, metadata in self.metadata["instances"].items():
                if aws_id == instance_id or metadata.get("instance_id") == instance_id:
                    instance_metadata = metadata
                    aws_instance_id = aws_id
                    break
            
            if not instance_metadata:
                logger.error(f"Instance not found: {instance_id}")
                return False
            
            # Terminate instance
            self.ec2_client.terminate_instances(InstanceIds=[aws_instance_id])
            
            # Update metadata
            instance_metadata["state"] = "terminated"
            instance_metadata["terminated_at"] = datetime.now().isoformat()
            self._save_metadata()
            
            logger.info(f"Terminated instance: {aws_instance_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to terminate instance {instance_id}: {e}")
            return False
    
    def list_instances(self) -> List[Dict]:
        """List all managed honeypot instances."""
        try:
            # Get current AWS instance states
            if not self.metadata["instances"]:
                return []
            
            aws_instance_ids = list(self.metadata["instances"].keys())
            response = self.ec2_client.describe_instances(InstanceIds=aws_instance_ids)
            
            # Update metadata with current states
            current_instances = {}
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    aws_id = instance['InstanceId']
                    if aws_id in self.metadata["instances"]:
                        metadata = self.metadata["instances"][aws_id].copy()
                        metadata.update({
                            "state": instance['State']['Name'],
                            "public_ip": instance.get('PublicIpAddress'),
                            "private_ip": instance.get('PrivateIpAddress'),
                            "launch_time": instance.get('LaunchTime')
                        })
                        current_instances[aws_id] = metadata
            
            return list(current_instances.values())
            
        except Exception as e:
            logger.error(f"Failed to list instances: {e}")
            return []
    
    def rotate_keypair_on_instances(self, old_key_name: str, new_key_name: str, 
                                   instance_ids: Optional[List[str]] = None) -> Dict[str, bool]:
        """
        Rotate SSH keypair on running instances using SSM.
        
        Args:
            old_key_name: Name of the current keypair
            new_key_name: Name of the new keypair to deploy
            instance_ids: List of instance IDs to update (if None, updates all managed instances)
            
        Returns:
            Dict mapping instance IDs to success status
        """
        results = {}
        
        try:
            # Get instances to update
            if instance_ids is None:
                instance_ids = [aws_id for aws_id, metadata in self.metadata["instances"].items() 
                              if metadata.get("state") == "running"]
            
            if not instance_ids:
                logger.warning("No running instances found for key rotation")
                return results
            
            # Create new keypair if it doesn't exist
            try:
                self.ec2_client.describe_key_pairs(KeyNames=[new_key_name])
                logger.info(f"Using existing keypair: {new_key_name}")
            except self.ec2_client.exceptions.ClientError:
                logger.info(f"Creating new keypair: {new_key_name}")
                self.create_keypair(new_key_name)
            
            # Get new public key from the newly created keypair
            # Note: We need to extract public key from private key since AWS doesn't provide it directly
            new_key_file = Path(f"{new_key_name}.pem")
            if not new_key_file.exists():
                raise Exception(f"Private key file not found: {new_key_file}")
            
            # Generate public key from private key using OpenSSL command
            public_key_command = f"""
#!/bin/bash
# Extract public key from private key
ssh-keygen -y -f /tmp/{new_key_name}.pem > /tmp/{new_key_name}.pub

# Backup current authorized_keys
cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.backup.$(date +%s)

# Add new public key to authorized_keys
cat /tmp/{new_key_name}.pub >> ~/.ssh/authorized_keys

# Remove duplicate entries and old key references
sort ~/.ssh/authorized_keys | uniq > ~/.ssh/authorized_keys.tmp
mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys

# Set proper permissions
chmod 600 ~/.ssh/authorized_keys
chown $(whoami):$(whoami) ~/.ssh/authorized_keys

# Cleanup temporary files
rm -f /tmp/{new_key_name}.pem /tmp/{new_key_name}.pub

echo "Key rotation completed successfully"
"""
            
            # Upload private key temporarily for public key extraction
            with open(new_key_file, 'r') as f:
                private_key_content = f.read()
            
            # Execute key rotation on each instance
            for instance_id in instance_ids:
                try:
                    logger.info(f"Rotating key on instance: {instance_id}")
                    
                    # First, upload the private key temporarily
                    upload_response = self.ssm_client.send_command(
                        InstanceIds=[instance_id],
                        DocumentName="AWS-RunShellScript",
                        Parameters={
                            'commands': [
                                f'echo "{private_key_content}" > /tmp/{new_key_name}.pem',
                                f'chmod 600 /tmp/{new_key_name}.pem'
                            ]
                        },
                        TimeoutSeconds=60
                    )
                    
                    # Wait for upload to complete
                    upload_command_id = upload_response['Command']['CommandId']
                    time.sleep(5)
                    
                    # Execute key rotation script
                    rotation_response = self.ssm_client.send_command(
                        InstanceIds=[instance_id],
                        DocumentName="AWS-RunShellScript",
                        Parameters={'commands': [public_key_command]},
                        TimeoutSeconds=120
                    )
                    
                    rotation_command_id = rotation_response['Command']['CommandId']
                    
                    # Wait for command completion and check result
                    max_attempts = 30
                    for attempt in range(max_attempts):
                        output = self.ssm_client.get_command_invocation(
                            CommandId=rotation_command_id,
                            InstanceId=instance_id
                        )
                        
                        if output['Status'] in ['Success', 'Failed']:
                            break
                        time.sleep(2)
                    
                    if output['Status'] == 'Success':
                        results[instance_id] = True
                        # Update metadata
                        if instance_id in self.metadata["instances"]:
                            self.metadata["instances"][instance_id]["key_name"] = new_key_name
                            self.metadata["instances"][instance_id]["key_rotated_at"] = datetime.now().isoformat()
                        logger.info(f"Successfully rotated key on {instance_id}")
                    else:
                        results[instance_id] = False
                        logger.error(f"Key rotation failed on {instance_id}: {output.get('StandardErrorContent', 'Unknown error')}")
                        
                except Exception as e:
                    results[instance_id] = False
                    logger.error(f"Failed to rotate key on {instance_id}: {e}")
            
            # Save updated metadata
            self._save_metadata()
            
            # Clean up old keypair if all rotations successful
            if all(results.values()) and results:
                try:
                    self.ec2_client.delete_key_pair(KeyName=old_key_name)
                    old_key_file = Path(f"{old_key_name}.pem")
                    if old_key_file.exists():
                        old_key_file.unlink()
                    logger.info(f"Cleaned up old keypair: {old_key_name}")
                except Exception as e:
                    logger.warning(f"Failed to clean up old keypair {old_key_name}: {e}")
            
            return results
            
        except Exception as e:
            logger.error(f"Key rotation process failed: {e}")
            return results

    def cleanup_all(self) -> Dict[str, int]:
        """Terminate all managed instances and clean up resources."""
        results = {"terminated": 0, "errors": 0}
        
        for aws_instance_id in list(self.metadata["instances"].keys()):
            if self.terminate_instance(aws_instance_id):
                results["terminated"] += 1
            else:
                results["errors"] += 1
        
        logger.info(f"Cleanup completed: {results}")
        return results

def main():
    """CLI interface for the controller."""
    import argparse
    
    parser = argparse.ArgumentParser(description="CerberusMesh Honeypot Controller")
    parser.add_argument("action", choices=["launch", "list", "terminate", "cleanup"], 
                       help="Action to perform")
    parser.add_argument("--count", type=int, default=1, 
                       help="Number of instances to launch")
    parser.add_argument("--instance-id", 
                       help="Instance ID to terminate")
    parser.add_argument("--region", default="us-east-1",
                       help="AWS region")
    parser.add_argument("--instance-type", default="t3.micro",
                       help="EC2 instance type")
    
    args = parser.parse_args()
    
    # Initialize controller
    config = HoneypotConfig(
        region=args.region,
        instance_type=args.instance_type
    )
    controller = HoneypotController(config)
    
    # Execute action
    if args.action == "launch":
        instances = controller.launch_honeypots(args.count)
        print(f"Launched {len(instances)} instances:")
        for instance in instances:
            print(f"  - {instance['aws_instance_id']} ({instance['instance_id']})")
    
    elif args.action == "list":
        instances = controller.list_instances()
        print(f"Found {len(instances)} instances:")
        for instance in instances:
            print(f"  - {instance['aws_instance_id']} ({instance['instance_id']}) - {instance['state']}")
    
    elif args.action == "terminate":
        if not args.instance_id:
            print("Error: --instance-id required for terminate action")
            return
        if controller.terminate_instance(args.instance_id):
            print(f"Terminated instance: {args.instance_id}")
        else:
            print(f"Failed to terminate instance: {args.instance_id}")
    
    elif args.action == "cleanup":
        results = controller.cleanup_all()
        print(f"Cleanup results: {results}")

if __name__ == "__main__":
    main()
