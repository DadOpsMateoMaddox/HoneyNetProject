# Observability and Monitoring Stack for CerberusMesh SOAR Platform
# Enterprise-grade monitoring with OpenSearch, Grafana, and comprehensive logging

# S3 Bucket for logs and data storage
resource "aws_s3_bucket" "logs" {
  bucket = "${local.name_prefix}-logs-${data.aws_caller_identity.current.account_id}"
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-logs-bucket"
    Purpose = "log-storage"
  })
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.cerberusmesh.arn
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  rule {
    id     = "log_retention"
    status = "Enabled"
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }
    
    expiration {
      days = 2555  # 7 years retention for compliance
    }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# OpenSearch Domain for log analytics and SIEM integration
resource "aws_opensearch_domain" "main" {
  domain_name    = "${local.name_prefix}-opensearch"
  engine_version = "OpenSearch_2.3"
  
  cluster_config {
    instance_type            = var.opensearch_instance_type
    instance_count           = var.opensearch_instance_count
    dedicated_master_enabled = true
    master_instance_type     = "t3.medium.search"
    master_instance_count    = 3
    zone_awareness_enabled   = true
    
    zone_awareness_config {
      availability_zone_count = 3
    }
  }
  
  vpc_options {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.opensearch.id]
  }
  
  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = 100
    iops        = 3000
    throughput  = 125
  }
  
  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.cerberusmesh.arn
  }
  
  node_to_node_encryption {
    enabled = true
  }
  
  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
  
  log_publishing_options {
    cloudwatch_log_group_arn = "${aws_cloudwatch_log_group.opensearch_index.arn}:*"
    log_type                 = "INDEX_SLOW_LOGS"
    enabled                  = true
  }
  
  log_publishing_options {
    cloudwatch_log_group_arn = "${aws_cloudwatch_log_group.opensearch_search.arn}:*"
    log_type                 = "SEARCH_SLOW_LOGS"
    enabled                  = true
  }
  
  log_publishing_options {
    cloudwatch_log_group_arn = "${aws_cloudwatch_log_group.opensearch_application.arn}:*"
    log_type                 = "ES_APPLICATION_LOGS"
    enabled                  = true
  }
  
  advanced_options = {
    "rest.action.multi.allow_explicit_index" = "true"
    "indices.fielddata.cache.size"           = "20"
    "indices.query.bool.max_clause_count"    = "1024"
  }
  
  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action   = "es:*"
        Resource = "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${local.name_prefix}-opensearch/*"
        Condition = {
          IpAddress = {
            "aws:sourceIp" = [var.vpc_cidr]
          }
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-opensearch"
    Purpose = "log-analytics-siem"
  })
  
  depends_on = [
    aws_cloudwatch_log_group.opensearch_index,
    aws_cloudwatch_log_group.opensearch_search,
    aws_cloudwatch_log_group.opensearch_application
  ]
}

# CloudWatch Log Groups for OpenSearch
resource "aws_cloudwatch_log_group" "opensearch_index" {
  name              = "/aws/opensearch/domains/${local.name_prefix}/index-slow"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.cerberusmesh.arn
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-opensearch-index-logs"
  })
}

resource "aws_cloudwatch_log_group" "opensearch_search" {
  name              = "/aws/opensearch/domains/${local.name_prefix}/search-slow"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.cerberusmesh.arn
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-opensearch-search-logs"
  })
}

resource "aws_cloudwatch_log_group" "opensearch_application" {
  name              = "/aws/opensearch/domains/${local.name_prefix}/application"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.cerberusmesh.arn
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-opensearch-app-logs"
  })
}

# Kinesis Data Firehose for log streaming
resource "aws_kinesis_firehose_delivery_stream" "logs" {
  name        = "${local.name_prefix}-logs-stream"
  destination = "extended_s3"
  
  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = aws_s3_bucket.logs.arn
    prefix     = "logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/"
    
    buffer_size     = 128
    buffer_interval = 60
    
    compression_format = "GZIP"
    
    processing_configuration {
      enabled = true
      
      processors {
        type = "Lambda"
        
        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = aws_lambda_function.log_processor.arn
        }
      }
    }
    
    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose.name
      log_stream_name = "delivery"
    }
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-logs-firehose"
  })
}

# IAM Role for Kinesis Firehose
resource "aws_iam_role" "firehose" {
  name = "${local.name_prefix}-firehose-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
      }
    ]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy" "firehose" {
  name = "${local.name_prefix}-firehose-policy"
  role = aws_iam_role.firehose.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:DeleteObject"
        ]
        Resource = [
          "${aws_s3_bucket.logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:ListBucketByTags",
          "s3:ListBucketMultipartUploads",
          "s3:GetBucketLocation"
        ]
        Resource = [
          aws_s3_bucket.logs.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = [
          aws_lambda_function.log_processor.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "${aws_cloudwatch_log_group.firehose.arn}:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [
          aws_kms_key.cerberusmesh.arn
        ]
      }
    ]
  })
}

# CloudWatch Log Group for Firehose
resource "aws_cloudwatch_log_group" "firehose" {
  name              = "/aws/kinesisfirehose/${local.name_prefix}-logs"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.cerberusmesh.arn
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-firehose-logs"
  })
}

# Lambda function for log processing
resource "aws_lambda_function" "log_processor" {
  filename         = "log_processor.zip"
  function_name    = "${local.name_prefix}-log-processor"
  role            = aws_iam_role.lambda_log_processor.arn
  handler         = "index.handler"
  runtime         = "python3.11"
  timeout         = 300
  
  environment {
    variables = {
      OPENSEARCH_ENDPOINT = aws_opensearch_domain.main.endpoint
    }
  }
  
  kms_key_arn = aws_kms_key.cerberusmesh.arn
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-log-processor"
  })
}

# Create the Lambda deployment package
data "archive_file" "log_processor" {
  type        = "zip"
  output_path = "log_processor.zip"
  
  source {
    content = <<EOF
import json
import base64
import gzip
import boto3
import os
from datetime import datetime

def handler(event, context):
    """Process logs and enrich with threat intelligence."""
    
    output = []
    
    for record in event['records']:
        # Decode the data
        compressed_payload = base64.b64decode(record['data'])
        uncompressed_payload = gzip.decompress(compressed_payload)
        data = json.loads(uncompressed_payload)
        
        # Enrich log data
        enriched_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'original_data': data,
            'enrichment': {
                'processed_by': 'cerberusmesh-log-processor',
                'version': '1.0'
            }
        }
        
        # Encode the enriched data
        output_record = {
            'recordId': record['recordId'],
            'result': 'Ok',
            'data': base64.b64encode(
                json.dumps(enriched_data).encode('utf-8')
            ).decode('utf-8')
        }
        
        output.append(output_record)
    
    return {'records': output}
EOF
    filename = "index.py"
  }
}

# IAM Role for Lambda log processor
resource "aws_iam_role" "lambda_log_processor" {
  name = "${local.name_prefix}-lambda-log-processor-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_log_processor.name
}

resource "aws_iam_role_policy" "lambda_log_processor" {
  name = "${local.name_prefix}-lambda-log-processor-policy"
  role = aws_iam_role.lambda_log_processor.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "es:ESHttpPost",
          "es:ESHttpPut"
        ]
        Resource = [
          "${aws_opensearch_domain.main.arn}/*"
        ]
      }
    ]
  })
}

# CloudWatch Dashboard for SOAR metrics
resource "aws_cloudwatch_dashboard" "soar_metrics" {
  dashboard_name = "${local.name_prefix}-soar-dashboard"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/EKS", "cluster_failed_request_count", "ClusterName", aws_eks_cluster.main.name],
            [".", "cluster_request_total", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "EKS Cluster Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", aws_db_instance.postgresql.id],
            [".", "DatabaseConnections", ".", "."],
            [".", "ReadLatency", ".", "."],
            [".", "WriteLatency", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "RDS Performance Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/ElastiCache", "CPUUtilization", "CacheClusterId", aws_elasticache_replication_group.redis.id],
            [".", "CurrConnections", ".", "."],
            [".", "NetworkBytesIn", ".", "."],
            [".", "NetworkBytesOut", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "Redis Cache Metrics"
          period  = 300
        }
      }
    ]
  })
  
  depends_on = [
    aws_eks_cluster.main,
    aws_db_instance.postgresql,
    aws_elasticache_replication_group.redis
  ]
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "high_cpu_usage" {
  alarm_name          = "${local.name_prefix}-high-cpu-usage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors RDS CPU utilization"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.postgresql.id
  }
  
  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "high_memory_usage" {
  alarm_name          = "${local.name_prefix}-high-memory-usage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "FreeableMemory"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "1000000000"  # 1GB in bytes
  alarm_description   = "This metric monitors RDS memory usage"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.postgresql.id
  }
  
  tags = local.common_tags
}

# SNS Topic for alerts
resource "aws_sns_topic" "alerts" {
  name              = "${local.name_prefix}-alerts"
  kms_master_key_id = aws_kms_key.cerberusmesh.arn
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-alerts-topic"
  })
}

# MSK Kafka Cluster for event streaming
resource "aws_msk_cluster" "kafka" {
  cluster_name           = "${local.name_prefix}-kafka"
  kafka_version         = "3.4.0"
  number_of_broker_nodes = 3
  
  broker_node_group_info {
    instance_type  = "kafka.t3.small"
    client_subnets = aws_subnet.private[*].id
    storage_info {
      ebs_storage_info {
        volume_size = 100
      }
    }
    security_groups = [aws_security_group.msk.id]
  }
  
  encryption_info {
    encryption_at_rest_kms_key_arn = aws_kms_key.cerberusmesh.arn
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }
  
  configuration_info {
    arn      = aws_msk_configuration.kafka.arn
    revision = aws_msk_configuration.kafka.latest_revision
  }
  
  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.msk.name
      }
      firehose {
        enabled         = true
        delivery_stream = aws_kinesis_firehose_delivery_stream.logs.name
      }
    }
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-kafka-cluster"
    Purpose = "event-streaming"
  })
}

# MSK Configuration
resource "aws_msk_configuration" "kafka" {
  kafka_versions = ["3.4.0"]
  name           = "${local.name_prefix}-kafka-config"
  
  server_properties = <<PROPERTIES
auto.create.topics.enable=false
default.replication.factor=3
min.insync.replicas=2
num.io.threads=8
num.network.threads=5
num.partitions=3
num.replica.fetchers=2
replica.lag.time.max.ms=30000
socket.receive.buffer.bytes=102400
socket.request.max.bytes=104857600
socket.send.buffer.bytes=102400
unclean.leader.election.enable=false
PROPERTIES
}

# Security Group for MSK
resource "aws_security_group" "msk" {
  name_prefix = "${local.name_prefix}-msk-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for MSK Kafka cluster"
  
  ingress {
    description     = "Kafka from EKS nodes"
    from_port       = 9092
    to_port         = 9094
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_nodes.id]
  }
  
  ingress {
    description     = "Zookeeper from EKS nodes"
    from_port       = 2181
    to_port         = 2181
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_nodes.id]
  }
  
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-msk-sg"
  })
  
  lifecycle {
    create_before_destroy = true
  }
}

# CloudWatch Log Group for MSK
resource "aws_cloudwatch_log_group" "msk" {
  name              = "/aws/msk/${local.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.cerberusmesh.arn
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-msk-logs"
  })
}

# Outputs
output "opensearch_endpoint" {
  description = "OpenSearch domain endpoint"
  value       = aws_opensearch_domain.main.endpoint
  sensitive   = true
}

output "opensearch_kibana_endpoint" {
  description = "OpenSearch Kibana endpoint"
  value       = aws_opensearch_domain.main.kibana_endpoint
  sensitive   = true
}

output "s3_logs_bucket" {
  description = "S3 bucket for logs"
  value       = aws_s3_bucket.logs.bucket
}

output "kafka_bootstrap_brokers" {
  description = "MSK Kafka bootstrap brokers"
  value       = aws_msk_cluster.kafka.bootstrap_brokers
  sensitive   = true
}

output "kafka_bootstrap_brokers_tls" {
  description = "MSK Kafka bootstrap brokers TLS"
  value       = aws_msk_cluster.kafka.bootstrap_brokers_tls
  sensitive   = true
}

output "cloudwatch_dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.soar_metrics.dashboard_name}"
}

output "sns_alerts_topic_arn" {
  description = "SNS topic ARN for alerts"
  value       = aws_sns_topic.alerts.arn
}
