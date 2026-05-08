# Cyber Global Shield — Terraform Infrastructure
# Déploiement sur AWS EKS avec tous les composants

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  backend "s3" {
    bucket         = "cgs-terraform-state"
    key            = "infrastructure/terraform.tfstate"
    region         = "eu-west-3"
    encrypt        = true
    dynamodb_table = "cgs-terraform-locks"
  }
}

# Provider configuration
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "CyberGlobalShield"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# VPC
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "cgs-${var.environment}-vpc"
  cidr = var.vpc_cidr

  azs             = var.availability_zones
  private_subnets = var.private_subnet_cidrs
  public_subnets  = var.public_subnet_cidrs

  enable_nat_gateway     = true
  single_nat_gateway     = var.environment != "production"
  enable_dns_hostnames   = true
  enable_dns_support     = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# EKS Cluster
module "eks" {
  source = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = "cgs-${var.environment}-cluster"
  cluster_version = "1.29"

  cluster_endpoint_public_access = var.environment != "production"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # EKS Managed Node Groups
  eks_managed_node_groups = {
    cgs_nodes = {
      desired_size = var.node_desired_size
      min_size     = var.node_min_size
      max_size     = var.node_max_size

      instance_types = var.node_instance_types

      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 100
            volume_type           = "gp3"
            encrypted             = true
            delete_on_termination = true
          }
        }
      }

      tags = {
        "k8s.io/cluster-autoscaler/enabled"             = "true"
        "k8s.io/cluster-autoscaler/cgs-cluster" = "owned"
      }
    }
  }

  # Cluster add-ons
  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
    aws-ebs-csi-driver = {
      most_recent = true
    }
  }

  # Node security group
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
    ingress_cluster_all = {
      description = "Cluster to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      source_cluster_security_group = true
    }
    egress_all = {
      description      = "Node all egress"
      protocol         = "-1"
      from_port        = 0
      to_port          = 0
      type             = "egress"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
    }
  }
}

# RDS for PostgreSQL (metadata)
module "rds" {
  source = "terraform-aws-modules/rds/aws"
  version = "~> 6.0"

  identifier = "cgs-${var.environment}-postgres"

  engine               = "postgres"
  engine_version       = "16.3"
  family               = "postgres16"
  major_engine_version = "16"
  instance_class       = var.rds_instance_class

  allocated_storage     = var.rds_allocated_storage
  max_allocated_storage = var.rds_max_allocated_storage
  storage_encrypted     = true
  storage_type          = "gp3"

  db_name  = "cyber_shield"
  username = var.rds_username
  password = random_password.rds_password.result
  port     = 5432

  multi_az               = var.environment == "production"
  db_subnet_group_name   = module.vpc.database_subnet_group
  vpc_security_group_ids = [aws_security_group.rds.id]

  backup_window      = "03:00-04:00"
  maintenance_window = "Mon:04:00-Mon:05:00"

  backup_retention_period = var.environment == "production" ? 30 : 7
  deletion_protection     = var.environment == "production"
  skip_final_snapshot     = var.environment != "production"

  enabled_cloudwatch_logs_exports = ["postgresql"]
}

# ElastiCache for Redis
module "elasticache_redis" {
  source = "terraform-aws-modules/elasticache/aws"
  version = "~> 1.0"

  cluster_id = "cgs-${var.environment}-redis"

  engine         = "redis"
  engine_version = "7.1"
  node_type      = var.redis_node_type

  num_cache_nodes = var.environment == "production" ? 2 : 1

  subnet_group_name = module.vpc.elasticache_subnet_group
  security_group_ids = [aws_security_group.redis.id]

  parameter_group_family = "redis7"

  maintenance_window = "sun:05:00-sun:06:00"
  snapshot_window    = "03:00-04:00"
  snapshot_retention_limit = var.environment == "production" ? 7 : 1
}

# MSK for Kafka
module "msk_kafka" {
  source = "terraform-aws-modules/msk-kafka-cluster/aws"
  version = "~> 2.0"

  cluster_name = "cgs-${var.environment}-kafka"

  kafka_version = "3.7.0"
  number_of_broker_nodes = var.kafka_broker_count

  broker_node_client_subnets  = module.vpc.private_subnets
  broker_node_security_groups = [aws_security_group.kafka.id]

  broker_node_storage_info = {
    ebs_storage_info = {
      volume_size = var.kafka_volume_size
    }
  }

  instance_type = var.kafka_instance_type

  encryption_in_transit_client_broker = "TLS"
  encryption_in_transit_in_cluster    = true

  enhanced_monitoring = "PER_TOPIC_PER_PARTITION"

  tags = {
    Purpose = "Cyber Global Shield Event Streaming"
  }
}

# S3 Buckets
resource "aws_s3_bucket" "backups" {
  bucket = "cgs-${var.environment}-backups"
}

resource "aws_s3_bucket" "models" {
  bucket = "cgs-${var.environment}-models"
}

resource "aws_s3_bucket" "logs_archive" {
  bucket = "cgs-${var.environment}-logs-archive"
}

resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# IAM Roles
resource "aws_iam_role" "eks_irsa" {
  name = "cgs-${var.environment}-irsa"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = module.eks.oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${module.eks.oidc_provider}:sub" = "system:serviceaccount:cgs:cgs-service-account"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "eks_s3_access" {
  name = "cgs-${var.environment}-s3-access"
  role = aws_iam_role.eks_irsa.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:DeleteObject",
        ]
        Resource = [
          aws_s3_bucket.backups.arn,
          "${aws_s3_bucket.backups.arn}/*",
          aws_s3_bucket.models.arn,
          "${aws_s3_bucket.models.arn}/*",
          aws_s3_bucket.logs_archive.arn,
          "${aws_s3_bucket.logs_archive.arn}/*",
        ]
      }
    ]
  })
}

# Security Groups
resource "aws_security_group" "rds" {
  name        = "cgs-${var.environment}-rds"
  description = "RDS PostgreSQL security group"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }
}

resource "aws_security_group" "redis" {
  name        = "cgs-${var.environment}-redis"
  description = "Redis security group"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }
}

resource "aws_security_group" "kafka" {
  name        = "cgs-${var.environment}-kafka"
  description = "Kafka security group"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 9092
    to_port         = 9098
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }
}

# Random passwords
resource "random_password" "rds_password" {
  length  = 32
  special = false
}

resource "random_password" "jwt_secret" {
  length  = 64
  special = false
}

# Secrets Manager
resource "aws_secretsmanager_secret" "cgs_secrets" {
  name = "cgs-${var.environment}-secrets"
}

resource "aws_secretsmanager_secret_version" "cgs_secrets" {
  secret_id = aws_secretsmanager_secret.cgs_secrets.id
  secret_string = jsonencode({
    rds_password     = random_password.rds_password.result
    jwt_secret       = random_password.jwt_secret.result
    clickhouse_password = random_password.rds_password.result
  })
}

# Outputs
output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "rds_endpoint" {
  description = "RDS endpoint"
  value       = module.rds.db_instance_endpoint
}

output "redis_endpoint" {
  description = "Redis endpoint"
  value       = module.elasticache_redis.primary_endpoint_address
}

output "kafka_bootstrap_brokers" {
  description = "Kafka bootstrap brokers"
  value       = module.msk_kafka.bootstrap_brokers_tls
}

output "s3_backups_bucket" {
  description = "S3 backups bucket"
  value       = aws_s3_bucket.backups.id
}

output "s3_models_bucket" {
  description = "S3 models bucket"
  value       = aws_s3_bucket.models.id
}
