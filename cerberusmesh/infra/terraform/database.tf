# RDS PostgreSQL Database for CerberusMesh SOAR Platform
# High-availability, encrypted, production-ready database configuration

# DB Subnet Group
resource "aws_db_subnet_group" "main" {
  name       = "${local.name_prefix}-db-subnet-group"
  subnet_ids = aws_subnet.database[*].id
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db-subnet-group"
  })
}

# DB Parameter Group
resource "aws_db_parameter_group" "postgresql" {
  family = "postgres15"
  name   = "${local.name_prefix}-postgres-params"
  
  # Performance and security parameters
  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements"
  }
  
  parameter {
    name  = "log_statement"
    value = "all"
  }
  
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"  # Log slow queries (1 second+)
  }
  
  parameter {
    name  = "max_connections"
    value = "200"
  }
  
  parameter {
    name  = "work_mem"
    value = "4096"  # 4MB
  }
  
  parameter {
    name  = "maintenance_work_mem"
    value = "2097152"  # 2GB
  }
  
  parameter {
    name  = "effective_cache_size"
    value = "8388608"  # 8GB
  }
  
  parameter {
    name  = "checkpoint_completion_target"
    value = "0.9"
  }
  
  parameter {
    name  = "wal_buffers"
    value = "16384"  # 16MB
  }
  
  parameter {
    name  = "default_statistics_target"
    value = "100"
  }
  
  parameter {
    name  = "random_page_cost"
    value = "1.1"  # Optimized for SSD
  }
  
  parameter {
    name  = "effective_io_concurrency"
    value = "200"
  }
  
  parameter {
    name  = "max_worker_processes"
    value = "8"
  }
  
  parameter {
    name  = "max_parallel_workers_per_gather"
    value = "4"
  }
  
  parameter {
    name  = "max_parallel_workers"
    value = "8"
  }
  
  parameter {
    name  = "max_parallel_maintenance_workers"
    value = "4"
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-postgres-params"
  })
}

# RDS Instance
resource "aws_db_instance" "postgresql" {
  identifier = "${local.name_prefix}-postgres"
  
  # Engine configuration
  engine                = "postgres"
  engine_version        = "15.3"
  instance_class        = var.rds_instance_class
  allocated_storage     = 100
  max_allocated_storage = 1000
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id           = aws_kms_key.cerberusmesh.arn
  
  # Database configuration
  db_name  = "cerberusmesh"
  username = "cerberusmesh"
  password = random_password.database_passwords["postgres"].result
  port     = 5432
  
  # Network configuration
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false
  
  # Backup configuration
  backup_retention_period   = var.backup_retention_period
  backup_window            = "03:00-04:00"  # UTC
  maintenance_window       = "sun:04:00-sun:05:00"  # UTC
  delete_automated_backups = false
  deletion_protection      = var.enable_deletion_protection
  
  # Performance and monitoring
  parameter_group_name        = aws_db_parameter_group.postgresql.name
  performance_insights_enabled = var.monitoring_enabled
  performance_insights_kms_key_id = aws_kms_key.cerberusmesh.arn
  performance_insights_retention_period = 7
  monitoring_interval         = var.monitoring_enabled ? 60 : 0
  monitoring_role_arn        = var.monitoring_enabled ? aws_iam_role.rds_enhanced_monitoring[0].arn : null
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  
  # Final snapshot
  skip_final_snapshot       = false
  final_snapshot_identifier = "${local.name_prefix}-postgres-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-postgres"
    Purpose = "adversary-session-storage"
  })
  
  lifecycle {
    prevent_destroy = true
    ignore_changes = [password]
  }
}

# RDS Enhanced Monitoring Role
resource "aws_iam_role" "rds_enhanced_monitoring" {
  count = var.monitoring_enabled ? 1 : 0
  
  name = "${local.name_prefix}-rds-monitoring-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  count = var.monitoring_enabled ? 1 : 0
  
  role       = aws_iam_role.rds_enhanced_monitoring[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# Read replica for reporting and analytics
resource "aws_db_instance" "postgresql_replica" {
  identifier = "${local.name_prefix}-postgres-replica"
  
  # Replica configuration
  replicate_source_db = aws_db_instance.postgresql.identifier
  instance_class      = var.rds_instance_class
  
  # Performance and monitoring
  performance_insights_enabled = var.monitoring_enabled
  performance_insights_kms_key_id = aws_kms_key.cerberusmesh.arn
  monitoring_interval = var.monitoring_enabled ? 60 : 0
  monitoring_role_arn = var.monitoring_enabled ? aws_iam_role.rds_enhanced_monitoring[0].arn : null
  
  # Network configuration
  publicly_accessible = false
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-postgres-replica"
    Purpose = "reporting-analytics"
  })
  
  lifecycle {
    prevent_destroy = true
  }
}

# ElastiCache Redis Subnet Group
resource "aws_elasticache_subnet_group" "main" {
  name       = "${local.name_prefix}-redis-subnet-group"
  subnet_ids = aws_subnet.private[*].id
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis-subnet-group"
  })
}

# ElastiCache Parameter Group
resource "aws_elasticache_parameter_group" "redis" {
  family = "redis7.x"
  name   = "${local.name_prefix}-redis-params"
  
  # Redis configuration parameters
  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }
  
  parameter {
    name  = "timeout"
    value = "300"
  }
  
  parameter {
    name  = "tcp-keepalive"
    value = "300"
  }
  
  parameter {
    name  = "maxclients"
    value = "10000"
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis-params"
  })
}

# ElastiCache Replication Group
resource "aws_elasticache_replication_group" "redis" {
  replication_group_id         = "${local.name_prefix}-redis"
  description                  = "Redis cluster for CerberusMesh session cache"
  
  # Cluster configuration
  node_type                    = var.elasticache_node_type
  port                         = 6379
  parameter_group_name         = aws_elasticache_parameter_group.redis.name
  
  # High availability configuration
  num_cache_clusters           = 3
  automatic_failover_enabled   = true
  multi_az_enabled            = true
  
  # Network configuration
  subnet_group_name           = aws_elasticache_subnet_group.main.name
  security_group_ids          = [aws_security_group.elasticache.id]
  
  # Security configuration
  at_rest_encryption_enabled  = true
  transit_encryption_enabled  = true
  auth_token                  = random_password.database_passwords["redis"].result
  kms_key_id                  = aws_kms_key.cerberusmesh.arn
  
  # Backup configuration
  snapshot_retention_limit    = 7
  snapshot_window            = "03:00-05:00"
  maintenance_window         = "sun:05:00-sun:07:00"
  
  # Logging
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis_slow.name
    destination_type = "cloudwatch-logs"
    log_format       = "text"
    log_type         = "slow-log"
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis"
    Purpose = "session-cache"
  })
  
  lifecycle {
    prevent_destroy = true
    ignore_changes = [auth_token]
  }
}

# CloudWatch Log Group for Redis
resource "aws_cloudwatch_log_group" "redis_slow" {
  name              = "/aws/elasticache/${local.name_prefix}/redis-slow"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.cerberusmesh.arn
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis-logs"
  })
}

# Secrets Manager for database credentials
resource "aws_secretsmanager_secret" "database_credentials" {
  for_each = toset(["postgres", "redis"])
  
  name                    = "${local.name_prefix}/${each.key}/credentials"
  description             = "Database credentials for ${each.key}"
  kms_key_id             = aws_kms_key.cerberusmesh.arn
  recovery_window_in_days = 7
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-${each.key}-credentials"
    Database = each.key
  })
}

resource "aws_secretsmanager_secret_version" "postgres_credentials" {
  secret_id = aws_secretsmanager_secret.database_credentials["postgres"].id
  
  secret_string = jsonencode({
    username = aws_db_instance.postgresql.username
    password = random_password.database_passwords["postgres"].result
    endpoint = aws_db_instance.postgresql.endpoint
    port     = aws_db_instance.postgresql.port
    dbname   = aws_db_instance.postgresql.db_name
  })
  
  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret_version" "redis_credentials" {
  secret_id = aws_secretsmanager_secret.database_credentials["redis"].id
  
  secret_string = jsonencode({
    auth_token = random_password.database_passwords["redis"].result
    endpoint   = aws_elasticache_replication_group.redis.configuration_endpoint_address
    port       = aws_elasticache_replication_group.redis.port
  })
  
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# DynamoDB Table for SOAR metadata
resource "aws_dynamodb_table" "soar_metadata" {
  name           = "${local.name_prefix}-soar-metadata"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "pk"
  range_key      = "sk"
  
  attribute {
    name = "pk"
    type = "S"
  }
  
  attribute {
    name = "sk"
    type = "S"
  }
  
  attribute {
    name = "gsi1pk"
    type = "S"
  }
  
  attribute {
    name = "gsi1sk"
    type = "S"
  }
  
  global_secondary_index {
    name     = "GSI1"
    hash_key = "gsi1pk"
    range_key = "gsi1sk"
  }
  
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.cerberusmesh.arn
  }
  
  point_in_time_recovery {
    enabled = true
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-soar-metadata"
    Purpose = "playbook-metadata"
  })
  
  lifecycle {
    prevent_destroy = true
  }
}

# Outputs
output "rds_instance_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.postgresql.endpoint
  sensitive   = true
}

output "rds_instance_id" {
  description = "RDS instance ID"
  value       = aws_db_instance.postgresql.id
}

output "rds_replica_endpoint" {
  description = "RDS replica endpoint"
  value       = aws_db_instance.postgresql_replica.endpoint
  sensitive   = true
}

output "redis_endpoint" {
  description = "Redis cluster endpoint"
  value       = aws_elasticache_replication_group.redis.configuration_endpoint_address
  sensitive   = true
}

output "redis_port" {
  description = "Redis cluster port"
  value       = aws_elasticache_replication_group.redis.port
}

output "database_secret_arns" {
  description = "Database credential secret ARNs"
  value = {
    postgres = aws_secretsmanager_secret.database_credentials["postgres"].arn
    redis    = aws_secretsmanager_secret.database_credentials["redis"].arn
  }
  sensitive = true
}

output "dynamodb_table_name" {
  description = "DynamoDB table name for SOAR metadata"
  value       = aws_dynamodb_table.soar_metadata.name
}

output "dynamodb_table_arn" {
  description = "DynamoDB table ARN for SOAR metadata"
  value       = aws_dynamodb_table.soar_metadata.arn
}
