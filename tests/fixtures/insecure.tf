terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "*"
    }
  }
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "company-data-bucket"
  acl    = "public-read"
}

resource "aws_ebs_volume" "app_data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

resource "aws_iam_policy" "admin" {
  name = "admin-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "azurerm_storage_account" "logs" {
  name                            = "companylogs"
  allow_nested_items_to_be_public = true
  min_tls_version                 = "TLS1_0"
}

resource "aws_instance" "worker" {
  ami           = "ami-0123456789"
  instance_type = "t3.micro"

  # aws_secret_access_key = "AKIAABCDEFGHIJKLMNOP"  # example of what NOT to do
}
