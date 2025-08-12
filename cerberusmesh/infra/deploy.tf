# CerberusMesh Infrastructure - Terraform Configuration
# This configuration provisions a VPC, subnets, security groups, and EC2 instances
# for the CerberusMesh honeypot platform.

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "CerberusMesh"
      Environment = var.environment
      ManagedBy   = "Terraform"
      CreatedAt   = timestamp()
    }
  }
}

# Variables
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "instance_count" {
  description = "Number of honeypot instances to create"
  type        = number
  default     = 2
}

variable "instance_type" {
  description = "EC2 instance type for honeypots"
  type        = string
  default     = "t3.micro"
}

variable "allowed_ips" {
  description = "IP addresses allowed to access the management interface"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # CHANGE THIS IN PRODUCTION
}

variable "honeypot_ports" {
  description = "Ports to expose on honeypot instances"
  type        = list(number)
  default     = [22, 23, 80, 443, 3389, 8080]
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.20.0/24"]
}

variable "key_name" {
  description = "Name of the AWS key pair for EC2 access"
  type        = string
  default     = "cerberusmesh-key"
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# VPC
resource "aws_vpc" "cerberusmesh_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "cerberusmesh-vpc-${var.environment}"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "cerberusmesh_igw" {
  vpc_id = aws_vpc.cerberusmesh_vpc.id
  
  tags = {
    Name = "cerberusmesh-igw-${var.environment}"
  }
}

# Public Subnets
resource "aws_subnet" "public_subnets" {
  count             = length(var.public_subnet_cidrs)
  vpc_id            = aws_vpc.cerberusmesh_vpc.id
  cidr_block        = var.public_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  map_public_ip_on_launch = true
  
  tags = {
    Name = "cerberusmesh-public-subnet-${count.index + 1}-${var.environment}"
    Type = "Public"
  }
}

# Private Subnets
resource "aws_subnet" "private_subnets" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.cerberusmesh_vpc.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = {
    Name = "cerberusmesh-private-subnet-${count.index + 1}-${var.environment}"
    Type = "Private"
  }
}

# Route Table for Public Subnets
resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.cerberusmesh_vpc.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.cerberusmesh_igw.id
  }
  
  tags = {
    Name = "cerberusmesh-public-rt-${var.environment}"
  }
}

# Route Table Associations for Public Subnets
resource "aws_route_table_association" "public_subnet_associations" {
  count          = length(aws_subnet.public_subnets)
  subnet_id      = aws_subnet.public_subnets[count.index].id
  route_table_id = aws_route_table.public_route_table.id
}

# NAT Gateway for Private Subnets (optional)
resource "aws_eip" "nat_eip" {
  domain = "vpc"
  
  tags = {
    Name = "cerberusmesh-nat-eip-${var.environment}"
  }
  
  depends_on = [aws_internet_gateway.cerberusmesh_igw]
}

resource "aws_nat_gateway" "nat_gateway" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_subnets[0].id
  
  tags = {
    Name = "cerberusmesh-nat-gateway-${var.environment}"
  }
  
  depends_on = [aws_internet_gateway.cerberusmesh_igw]
}

# Route Table for Private Subnets
resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.cerberusmesh_vpc.id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gateway.id
  }
  
  tags = {
    Name = "cerberusmesh-private-rt-${var.environment}"
  }
}

# Route Table Associations for Private Subnets
resource "aws_route_table_association" "private_subnet_associations" {
  count          = length(aws_subnet.private_subnets)
  subnet_id      = aws_subnet.private_subnets[count.index].id
  route_table_id = aws_route_table.private_route_table.id
}

# Security Group for Honeypots
resource "aws_security_group" "honeypot_sg" {
  name_prefix = "cerberusmesh-honeypot-"
  vpc_id      = aws_vpc.cerberusmesh_vpc.id
  description = "Security group for CerberusMesh honeypot instances"
  
  # Honeypot service ports (open to the world)
  dynamic "ingress" {
    for_each = var.honeypot_ports
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "Honeypot port ${ingress.value}"
    }
  }
  
  # Management SSH (restricted)
  ingress {
    from_port   = 2222
    to_port     = 2222
    protocol    = "tcp"
    cidr_blocks = var.allowed_ips
    description = "Management SSH"
  }
  
  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }
  
  tags = {
    Name = "cerberusmesh-honeypot-sg-${var.environment}"
  }
}

# Security Group for Management/Controller
resource "aws_security_group" "management_sg" {
  name_prefix = "cerberusmesh-management-"
  vpc_id      = aws_vpc.cerberusmesh_vpc.id
  description = "Security group for CerberusMesh management instances"
  
  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ips
    description = "SSH access"
  }
  
  # Dashboard web interface
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = var.allowed_ips
    description = "Dashboard web interface"
  }
  
  # API endpoints
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.allowed_ips
    description = "API endpoints"
  }
  
  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }
  
  tags = {
    Name = "cerberusmesh-management-sg-${var.environment}"
  }
}

# IAM Role for EC2 instances
resource "aws_iam_role" "ec2_role" {
  name = "cerberusmesh-ec2-role-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  
  tags = {
    Name = "cerberusmesh-ec2-role-${var.environment}"
  }
}

# IAM Policy for CloudWatch Logs
resource "aws_iam_role_policy" "ec2_cloudwatch_policy" {
  name = "cerberusmesh-cloudwatch-policy-${var.environment}"
  role = aws_iam_role.ec2_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM Instance Profile
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "cerberusmesh-ec2-profile-${var.environment}"
  role = aws_iam_role.ec2_role.name
  
  tags = {
    Name = "cerberusmesh-ec2-profile-${var.environment}"
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "cerberusmesh_logs" {
  name              = "/cerberusmesh/${var.environment}/honeypot"
  retention_in_days = 30
  
  tags = {
    Name = "cerberusmesh-logs-${var.environment}"
  }
}

# User Data Script for Honeypot Instances
locals {
  honeypot_user_data = base64encode(templatefile("${path.module}/scripts/honeypot_setup.sh", {
    log_group_name = aws_cloudwatch_log_group.cerberusmesh_logs.name
    aws_region     = var.aws_region
  }))
}

# Honeypot EC2 Instances
resource "aws_instance" "honeypot_instances" {
  count                  = var.instance_count
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.honeypot_sg.id]
  subnet_id              = aws_subnet.public_subnets[count.index % length(aws_subnet.public_subnets)].id
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name
  
  user_data = local.honeypot_user_data
  
  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
    
    tags = {
      Name = "cerberusmesh-honeypot-${count.index + 1}-root-${var.environment}"
    }
  }
  
  tags = {
    Name         = "cerberusmesh-honeypot-${count.index + 1}-${var.environment}"
    Type         = "Honeypot"
    InstanceRole = "honeypot"
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

# Application Load Balancer (optional, for management interface)
resource "aws_lb" "management_alb" {
  name               = "cerberusmesh-mgmt-alb-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.management_sg.id]
  subnets            = aws_subnet.public_subnets[*].id
  
  enable_deletion_protection = false
  
  tags = {
    Name = "cerberusmesh-management-alb-${var.environment}"
  }
}

# Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.cerberusmesh_vpc.id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public_subnets[*].id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private_subnets[*].id
}

output "honeypot_instance_ids" {
  description = "Instance IDs of honeypot servers"
  value       = aws_instance.honeypot_instances[*].id
}

output "honeypot_public_ips" {
  description = "Public IP addresses of honeypot instances"
  value       = aws_instance.honeypot_instances[*].public_ip
}

output "honeypot_private_ips" {
  description = "Private IP addresses of honeypot instances"
  value       = aws_instance.honeypot_instances[*].private_ip
}

output "management_alb_dns" {
  description = "DNS name of the management ALB"
  value       = aws_lb.management_alb.dns_name
}

output "security_group_honeypot_id" {
  description = "ID of the honeypot security group"
  value       = aws_security_group.honeypot_sg.id
}

output "security_group_management_id" {
  description = "ID of the management security group"
  value       = aws_security_group.management_sg.id
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.cerberusmesh_logs.name
}
