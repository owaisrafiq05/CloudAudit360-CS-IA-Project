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
  default = "ca360-vuln"
}

# Intentionally misconfigured S3 bucket (public, no encryption)
resource "aws_s3_bucket" "public_data" {
  bucket        = "${var.project_prefix}-public-data"
  force_destroy = true

  tags = {
    Environment = "vulnerable"
    Project     = "CloudAudit360"
  }
}

resource "aws_s3_bucket_public_access_block" "public_data" {
  bucket = aws_s3_bucket.public_data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Open security group (SSH/RDP world-open)
resource "aws_security_group" "open" {
  name        = "${var.project_prefix}-open-sg"
  description = "INTENTIONAL: open admin ports for vulnerable lab"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = "vulnerable"
    Project     = "CloudAudit360"
  }
}

# IAM user without MFA + admin policy (lab only)
resource "aws_iam_user" "demo_admin" {
  name = "${var.project_prefix}-demo-admin"

  tags = {
    Environment = "vulnerable"
    Project     = "CloudAudit360"
  }
}

resource "aws_iam_user_policy_attachment" "demo_admin" {
  user       = aws_iam_user.demo_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_access_key" "demo_admin" {
  user = aws_iam_user.demo_admin.name
}

# Unencrypted RDS (free-tier friendly)
resource "aws_db_instance" "vuln" {
  identifier              = "${var.project_prefix}-db"
  engine                  = "mysql"
  engine_version          = "8.0"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "admin"
  password                = "ChangeMeLabOnly1!"
  skip_final_snapshot     = true
  publicly_accessible     = true
  storage_encrypted       = false
  backup_retention_period = 0
  deletion_protection     = false

  tags = {
    Environment = "vulnerable"
    Project     = "CloudAudit360"
    criticality = "3"
  }
}

output "bucket_name" {
  value = aws_s3_bucket.public_data.bucket
}

output "security_group_id" {
  value = aws_security_group.open.id
}

output "iam_user" {
  value = aws_iam_user.demo_admin.name
}

output "db_identifier" {
  value = aws_db_instance.vuln.id
}
