#!/bin/bash
# CerberusMesh Honeypot Setup Script
# This script installs and configures Cowrie honeypot on Amazon Linux 2

set -e

LOG_GROUP_NAME="${log_group_name}"
AWS_REGION="${aws_region}"

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a /var/log/honeypot-setup.log
}

log_message "Starting CerberusMesh honeypot setup"

# Update system
log_message "Updating system packages"
yum update -y

# Install required packages
log_message "Installing required packages"
yum install -y \
    python3 \
    python3-pip \
    git \
    gcc \
    python3-devel \
    openssl-devel \
    libffi-devel \
    autoconf \
    automake \
    libtool \
    docker \
    awslogs

# Start and enable Docker
systemctl start docker
systemctl enable docker
usermod -a -G docker ec2-user

# Install CloudWatch agent
log_message "Installing CloudWatch agent"
wget https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm
rpm -U ./amazon-cloudwatch-agent.rpm

# Create cowrie user
log_message "Creating cowrie user"
useradd -r -s /bin/false cowrie
usermod -a -G docker cowrie

# Clone and setup Cowrie
log_message "Setting up Cowrie honeypot"
cd /opt
git clone https://github.com/cowrie/cowrie.git
cd cowrie

# Install Python dependencies
log_message "Installing Python dependencies"
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

# Configure Cowrie
log_message "Configuring Cowrie"
cp etc/cowrie.cfg.dist etc/cowrie.cfg

# Basic Cowrie configuration
cat > etc/cowrie.cfg << 'EOF'
[honeypot]
hostname = honeypot
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
share_path = share/cowrie
state_path = var/lib/cowrie
etc_path = etc
contents_path = honeyfs
txtcmds_path = txtcmds
sessions_path = var/lib/cowrie/sessions
arch = linux-x64-lsb

[ssh]
enabled = true
rsa_public_key = etc/ssh_host_rsa_key.pub
rsa_private_key = etc/ssh_host_rsa_key
dsa_public_key = etc/ssh_host_dsa_key.pub
dsa_private_key = etc/ssh_host_dsa_key
listen_endpoints = tcp:22:interface=0.0.0.0
version = SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2
forward_tunnel = false
auth_class = UserDB
auth_class_parameters = etc/userdb.txt

[telnet]
enabled = true
listen_endpoints = tcp:23:interface=0.0.0.0

[output_json]
enabled = true
logfile = var/log/cowrie/cowrie.json

[output_mysql]
enabled = false

[output_sqlite3]
enabled = true
database = var/lib/cowrie/cowrie.db

[output_syslog]
enabled = true
facility = USER
priority = INFO
EOF

# Generate SSH keys
log_message "Generating SSH host keys"
ssh-keygen -t rsa -b 2048 -f etc/ssh_host_rsa_key -N ""
ssh-keygen -t dsa -b 1024 -f etc/ssh_host_dsa_key -N ""

# Create default users
log_message "Setting up default users"
cat > etc/userdb.txt << 'EOF'
root:x:!root
root:x:!123456
root:x:*
admin:x:*
user:x:*
test:x:*
guest:x:*
oracle:x:*
postgres:x:*
mysql:x:*
ftpuser:x:*
EOF

# Set permissions
chown -R cowrie:cowrie /opt/cowrie
chmod 755 /opt/cowrie

# Create systemd service
log_message "Creating systemd service"
cat > /etc/systemd/system/cowrie.service << 'EOF'
[Unit]
Description=Cowrie SSH/Telnet Honeypot
After=network.target

[Service]
Type=forking
User=cowrie
Group=cowrie
ExecStart=/opt/cowrie/bin/cowrie start
ExecStop=/opt/cowrie/bin/cowrie stop
WorkingDirectory=/opt/cowrie
PIDFile=/opt/cowrie/var/run/cowrie.pid
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Configure CloudWatch Logs
log_message "Configuring CloudWatch logs"
cat > /etc/awslogs/awslogs.conf << EOF
[general]
state_file = /var/lib/awslogs/agent-state

[/var/log/messages]
file = /var/log/messages
log_group_name = ${LOG_GROUP_NAME}
log_stream_name = {instance_id}/system
datetime_format = %b %d %H:%M:%S

[/opt/cowrie/var/log/cowrie/cowrie.log]
file = /opt/cowrie/var/log/cowrie/cowrie.log
log_group_name = ${LOG_GROUP_NAME}
log_stream_name = {instance_id}/cowrie
datetime_format = %Y-%m-%d %H:%M:%S

[/opt/cowrie/var/log/cowrie/cowrie.json]
file = /opt/cowrie/var/log/cowrie/cowrie.json
log_group_name = ${LOG_GROUP_NAME}
log_stream_name = {instance_id}/cowrie-json
datetime_format = %Y-%m-%dT%H:%M:%S

[/var/log/honeypot-setup.log]
file = /var/log/honeypot-setup.log
log_group_name = ${LOG_GROUP_NAME}
log_stream_name = {instance_id}/setup
datetime_format = %Y-%m-%d %H:%M:%S
EOF

# Configure awslogs region
sed -i "s/region = us-east-1/region = ${AWS_REGION}/" /etc/awslogs/awscli.conf

# Create log rotation for Cowrie
log_message "Setting up log rotation"
cat > /etc/logrotate.d/cowrie << 'EOF'
/opt/cowrie/var/log/cowrie/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
}

/opt/cowrie/var/log/cowrie/*.json {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF

# Create monitoring script
log_message "Creating monitoring script"
cat > /opt/cowrie/monitor.py << 'EOF'
#!/usr/bin/env python3
"""
CerberusMesh Honeypot Monitor
Monitors honeypot activity and sends alerts
"""

import json
import time
import subprocess
import boto3
from datetime import datetime, timedelta

def check_cowrie_status():
    """Check if Cowrie is running"""
    try:
        result = subprocess.run(['systemctl', 'is-active', 'cowrie'], 
                              capture_output=True, text=True)
        return result.stdout.strip() == 'active'
    except:
        return False

def get_recent_attacks():
    """Get recent attack attempts from Cowrie logs"""
    try:
        with open('/opt/cowrie/var/log/cowrie/cowrie.json', 'r') as f:
            lines = f.readlines()
            recent_lines = lines[-100:]  # Get last 100 lines
            
        attacks = []
        for line in recent_lines:
            try:
                log_entry = json.loads(line)
                if log_entry.get('eventid') in ['cowrie.login.success', 'cowrie.login.failed']:
                    attacks.append(log_entry)
            except:
                continue
        
        return attacks
    except:
        return []

def main():
    print(f"Honeypot Monitor - {datetime.now()}")
    
    # Check Cowrie status
    if check_cowrie_status():
        print("✓ Cowrie is running")
    else:
        print("✗ Cowrie is not running - attempting restart")
        subprocess.run(['systemctl', 'restart', 'cowrie'])
    
    # Check recent attacks
    attacks = get_recent_attacks()
    print(f"✓ {len(attacks)} recent attack attempts logged")
    
    # Basic statistics
    if attacks:
        unique_ips = set(attack.get('src_ip', '') for attack in attacks)
        print(f"✓ {len(unique_ips)} unique attacking IP addresses")

if __name__ == "__main__":
    main()
EOF

chmod +x /opt/cowrie/monitor.py

# Create cron job for monitoring
log_message "Setting up monitoring cron job"
cat > /etc/cron.d/cowrie-monitor << 'EOF'
# CerberusMesh Honeypot Monitoring
*/5 * * * * cowrie /usr/bin/python3 /opt/cowrie/monitor.py >> /var/log/cowrie-monitor.log 2>&1
EOF

# Create attack statistics script
log_message "Creating attack statistics script"
cat > /opt/cowrie/stats.py << 'EOF'
#!/usr/bin/env python3
"""
CerberusMesh Attack Statistics Generator
Generates daily statistics from honeypot logs
"""

import json
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict

def generate_daily_stats():
    """Generate daily attack statistics"""
    try:
        # Connect to Cowrie SQLite database
        conn = sqlite3.connect('/opt/cowrie/var/lib/cowrie/cowrie.db')
        cursor = conn.cursor()
        
        # Get today's date
        today = datetime.now().date()
        yesterday = today - timedelta(days=1)
        
        # Query for login attempts
        cursor.execute("""
            SELECT src_ip, username, password, timestamp 
            FROM auth 
            WHERE DATE(timestamp) = ?
        """, (today,))
        
        login_attempts = cursor.fetchall()
        
        # Generate statistics
        stats = {
            'date': today.isoformat(),
            'total_login_attempts': len(login_attempts),
            'unique_ips': len(set(attempt[0] for attempt in login_attempts)),
            'top_usernames': {},
            'top_passwords': {},
            'top_ips': {}
        }
        
        # Count frequencies
        usernames = defaultdict(int)
        passwords = defaultdict(int)
        ips = defaultdict(int)
        
        for ip, username, password, timestamp in login_attempts:
            usernames[username] += 1
            passwords[password] += 1
            ips[ip] += 1
        
        # Get top 10 for each category
        stats['top_usernames'] = dict(sorted(usernames.items(), key=lambda x: x[1], reverse=True)[:10])
        stats['top_passwords'] = dict(sorted(passwords.items(), key=lambda x: x[1], reverse=True)[:10])
        stats['top_ips'] = dict(sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10])
        
        # Save stats
        with open(f'/opt/cowrie/var/log/cowrie/stats-{today}.json', 'w') as f:
            json.dump(stats, f, indent=2)
        
        print(f"Generated statistics for {today}")
        print(f"Total login attempts: {stats['total_login_attempts']}")
        print(f"Unique attacking IPs: {stats['unique_ips']}")
        
        conn.close()
        
    except Exception as e:
        print(f"Error generating statistics: {e}")

if __name__ == "__main__":
    generate_daily_stats()
EOF

chmod +x /opt/cowrie/stats.py

# Create daily stats cron job
cat >> /etc/cron.d/cowrie-monitor << 'EOF'
# Daily statistics generation
0 1 * * * cowrie /usr/bin/python3 /opt/cowrie/stats.py >> /var/log/cowrie-stats.log 2>&1
EOF

# Start and enable services
log_message "Starting services"
systemctl daemon-reload
systemctl enable cowrie
systemctl start cowrie
systemctl enable awslogs
systemctl start awslogs

# Create startup script
log_message "Creating startup script"
cat > /etc/rc.local << 'EOF'
#!/bin/bash
# CerberusMesh startup script

# Ensure services are running
systemctl start cowrie
systemctl start awslogs

# Log startup
echo "$(date): CerberusMesh honeypot startup completed" >> /var/log/honeypot-startup.log

exit 0
EOF

chmod +x /etc/rc.local

# Create instance metadata file
log_message "Creating instance metadata"
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
INSTANCE_TYPE=$(curl -s http://169.254.169.254/latest/meta-data/instance-type)
AVAILABILITY_ZONE=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)

cat > /opt/cowrie/instance-metadata.json << EOF
{
    "instance_id": "$INSTANCE_ID",
    "instance_type": "$INSTANCE_TYPE",
    "availability_zone": "$AVAILABILITY_ZONE",
    "public_ip": "$PUBLIC_IP",
    "private_ip": "$PRIVATE_IP",
    "setup_completed": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "cowrie_version": "$(cd /opt/cowrie && git describe --tags)",
    "honeypot_type": "cowrie",
    "project": "CerberusMesh"
}
EOF

# Final setup verification
log_message "Verifying setup"
sleep 10

if systemctl is-active --quiet cowrie; then
    log_message "✓ Cowrie honeypot is running successfully"
else
    log_message "✗ Cowrie failed to start - checking logs"
    journalctl -u cowrie -n 20
fi

if systemctl is-active --quiet awslogs; then
    log_message "✓ CloudWatch logs agent is running"
else
    log_message "✗ CloudWatch logs agent failed to start"
fi

# Test honeypot connectivity
log_message "Testing honeypot connectivity"
if ss -tuln | grep -q ":22 "; then
    log_message "✓ SSH honeypot is listening on port 22"
else
    log_message "✗ SSH honeypot is not listening on port 22"
fi

if ss -tuln | grep -q ":23 "; then
    log_message "✓ Telnet honeypot is listening on port 23"
else
    log_message "✗ Telnet honeypot is not listening on port 23"
fi

log_message "CerberusMesh honeypot setup completed successfully"

# Send completion notification to CloudWatch
aws logs put-log-events \
    --log-group-name "${LOG_GROUP_NAME}" \
    --log-stream-name "${INSTANCE_ID}/setup" \
    --log-events timestamp=$(date +%s000),message="CerberusMesh honeypot setup completed on ${INSTANCE_ID}" \
    --region "${AWS_REGION}" 2>/dev/null || true

log_message "Setup script finished"
EOF
