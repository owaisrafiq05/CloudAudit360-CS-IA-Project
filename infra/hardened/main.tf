terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "project_prefix" {
  type    = string
  default = "ca360-hard"
}

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "main" {
  description             = "CloudAudit360 hardened lab CMK"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Environment = "hardened"
    Project     = "CloudAudit360"
  }
}

resource "aws_s3_bucket" "secure_data" {
  bucket        = "${var.project_prefix}-secure-data"
  force_destroy = true

  tags = {
    Environment = "hardened"
    Project     = "CloudAudit360"
  }
}

resource "aws_s3_bucket_public_access_block" "secure_data" {
  bucket = aws_s3_bucket.secure_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_data" {
  bucket = aws_s3_bucket.secure_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "secure_data" {
  bucket = aws_s3_bucket.secure_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "tls_only" {
  bucket = aws_s3_bucket.secure_data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.secure_data.arn,
          "${aws_s3_bucket.secure_data.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_security_group" "restricted" {
  name        = "${var.project_prefix}-restricted-sg"
  description = "Restricted SG for hardened lab"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = "hardened"
    Project     = "CloudAudit360"
  }
}

resource "aws_cloudtrail" "org" {
  name                          = "${var.project_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.secure_data.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.main.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.tls_only]

  tags = {
    Environment = "hardened"
    Project     = "CloudAudit360"
  }
}

resource "aws_guardduty_detector" "main" {
  enable = true

  tags = {
    Environment = "hardened"
    Project     = "CloudAudit360"
  }
}

resource "aws_ebs_encryption_by_default" "main" {
  enabled = true
}

resource "aws_db_instance" "hard" {
  identifier              = "${var.project_prefix}-db"
  engine                  = "mysql"
  engine_version          = "8.0"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "admin"
  password                = "ChangeMeLabOnly1!"
  skip_final_snapshot     = true
  publicly_accessible     = false
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.main.arn
  backup_retention_period = 7
  deletion_protection     = false

  tags = {
    Environment = "hardened"
    Project     = "CloudAudit360"
    criticality = "3"
  }
}

resource "aws_iam_user" "demo_admin" {
  name = "${var.project_prefix}-demo-admin"

  tags = {
    Environment = "hardened"
    Project     = "CloudAudit360"
  }
}

resource "aws_iam_user_policy_attachment" "demo_admin_ro" {
  user       = aws_iam_user.demo_admin.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

output "bucket_name" {
  value = aws_s3_bucket.secure_data.bucket
}

output "kms_key_arn" {
  value = aws_kms_key.main.arn
}

output "guardduty_detector" {
  value = aws_guardduty_detector.main.id
}

output "db_identifier" {
  value = aws_db_instance.hard.id
}
