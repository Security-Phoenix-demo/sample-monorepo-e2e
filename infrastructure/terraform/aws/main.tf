# Vulnerable AWS Terraform configuration — adapted from KaiMonkey-vulnerable-iac
# DO NOT USE IN PRODUCTION

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  # Hardcoded credentials — never do this
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# S3 bucket with public access — data exposure risk
resource "aws_s3_bucket" "app_data" {
  bucket = "${var.env}-app-data-public"
  acl    = "public-read"

  # No encryption at rest
  tags = {
    Environment = var.env
    Name        = "app-data-public"
  }
}

# S3 bucket without versioning or logging
resource "aws_s3_bucket_public_access_block" "app_data" {
  bucket = aws_s3_bucket.app_data.id

  # All public access blocks DISABLED — intentionally vulnerable
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Security group open to the internet on all ports — CWE-284
resource "aws_security_group" "wide_open" {
  name        = "${var.env}-wide-open-sg"
  description = "Intentionally wide-open security group for demo"

  # Inbound: allow ALL traffic from anywhere
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Also allow SSH from anywhere
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Outbound: allow everything
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAM role with wildcard permissions — privilege escalation risk
resource "aws_iam_role" "overly_permissive" {
  name = "${var.env}-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy" "full_access" {
  name = "full-access"
  role = aws_iam_role.overly_permissive.id

  # Wildcard permissions — grants full AWS access
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# EC2 instance with no IMDSv2 enforcement and public IP
resource "aws_instance" "app_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  # Metadata service v1 accessible — SSRF vector for credential theft
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"  # should be "required" for IMDSv2
    http_put_response_hop_limit = 2
  }

  associate_public_ip_address = true
  security_groups             = [aws_security_group.wide_open.name]
  iam_instance_profile        = aws_iam_instance_profile.app_profile.name

  # User data with hardcoded secrets
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD=SuperSecret123
    export API_KEY=sk-prod-a1b2c3d4e5f6
    export AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCY
    curl -s http://app-internal:8080/setup?key=$API_KEY
  EOF

  root_block_device {
    # No encryption on root volume
    encrypted = false
  }

  tags = {
    Name        = "${var.env}-app-server"
    Environment = var.env
  }
}

resource "aws_iam_instance_profile" "app_profile" {
  name = "${var.env}-instance-profile"
  role = aws_iam_role.overly_permissive.name
}

# RDS instance without encryption, publicly accessible
resource "aws_db_instance" "app_db" {
  identifier        = "${var.env}-app-db"
  engine            = "postgres"
  engine_version    = "12.8"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  # Hardcoded credentials
  db_name  = "appdb"
  username = "admin"
  password = "password123"

  # Publicly accessible database — CWE-668
  publicly_accessible    = true
  skip_final_snapshot    = true
  deletion_protection    = false

  # No encryption at rest
  storage_encrypted = false

  # No automated backups
  backup_retention_period = 0

  # VPC security group allows 0.0.0.0/0
  vpc_security_group_ids = [aws_security_group.wide_open.id]

  tags = {
    Environment = var.env
  }
}

# CloudTrail disabled — no audit logging
# (intentionally absent to demonstrate missing audit trail)

# KMS key without rotation
resource "aws_kms_key" "no_rotation" {
  description             = "App key without rotation"
  enable_key_rotation     = false  # should be true
  deletion_window_in_days = 7
}
