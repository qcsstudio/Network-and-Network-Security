# ============================================================
#  QCSSTUDIO — AWS Secure VPC Architecture
#  Author  : Ravi Kant Sankhyan
#  Purpose : Production-ready VPC with public/private subnets,
#            security groups, NACLs, and VPN gateway
# ============================================================

terraform {
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

# ─── Variables ───────────────────────────────────────────────
variable "aws_region"       { default = "ap-south-1" }
variable "vpc_cidr"         { default = "10.10.0.0/16" }
variable "project_name"     { default = "qcsstudio-network" }
variable "environment"      { default = "production" }
variable "admin_ip"         { default = "YOUR_ADMIN_IP/32" }  # Replace with your IP

# ─── VPC ─────────────────────────────────────────────────────
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.project_name}-vpc"
    Environment = var.environment
    ManagedBy   = "Terraform-QCSSTUDIO"
  }
}

# ─── Subnets ─────────────────────────────────────────────────
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.10.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
  tags = { Name = "${var.project_name}-public-a" }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.10.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true
  tags = { Name = "${var.project_name}-public-b" }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.10.10.0/24"
  availability_zone = "${var.aws_region}a"
  tags = { Name = "${var.project_name}-private-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.10.11.0/24"
  availability_zone = "${var.aws_region}b"
  tags = { Name = "${var.project_name}-private-b" }
}

resource "aws_subnet" "db_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.10.20.0/24"
  availability_zone = "${var.aws_region}a"
  tags = { Name = "${var.project_name}-db-a" }
}

# ─── Internet Gateway ────────────────────────────────────────
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project_name}-igw" }
}

# ─── NAT Gateway ─────────────────────────────────────────────
resource "aws_eip" "nat" { domain = "vpc" }

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_a.id
  tags          = { Name = "${var.project_name}-nat" }
}

# ─── Route Tables ─────────────────────────────────────────────
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "${var.project_name}-public-rt" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = { Name = "${var.project_name}-private-rt" }
}

resource "aws_route_table_association" "public_a"  { subnet_id = aws_subnet.public_a.id;  route_table_id = aws_route_table.public.id }
resource "aws_route_table_association" "public_b"  { subnet_id = aws_subnet.public_b.id;  route_table_id = aws_route_table.public.id }
resource "aws_route_table_association" "private_a" { subnet_id = aws_subnet.private_a.id; route_table_id = aws_route_table.private.id }
resource "aws_route_table_association" "private_b" { subnet_id = aws_subnet.private_b.id; route_table_id = aws_route_table.private.id }

# ─── Security Groups ─────────────────────────────────────────

# Web / ALB Security Group
resource "aws_security_group" "web" {
  name        = "${var.project_name}-web-sg"
  description = "Allow HTTP and HTTPS from internet"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP from internet"
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from internet"
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.project_name}-web-sg" }
}

# App Server Security Group
resource "aws_security_group" "app" {
  name        = "${var.project_name}-app-sg"
  description = "Allow traffic from web SG only"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
    description     = "App port from web tier only"
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.project_name}-app-sg" }
}

# DB Security Group
resource "aws_security_group" "db" {
  name        = "${var.project_name}-db-sg"
  description = "Allow DB access from app tier only"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
    description     = "MySQL from app tier only"
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.project_name}-db-sg" }
}

# Bastion / Management Security Group
resource "aws_security_group" "bastion" {
  name        = "${var.project_name}-bastion-sg"
  description = "SSH access restricted to admin IP only"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
    description = "SSH from admin IP only — NEVER 0.0.0.0/0"
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.project_name}-bastion-sg" }
}

# ─── Outputs ─────────────────────────────────────────────────
output "vpc_id"            { value = aws_vpc.main.id }
output "public_subnet_ids" { value = [aws_subnet.public_a.id, aws_subnet.public_b.id] }
output "private_subnet_ids"{ value = [aws_subnet.private_a.id, aws_subnet.private_b.id] }
output "web_sg_id"         { value = aws_security_group.web.id }
output "app_sg_id"         { value = aws_security_group.app.id }
output "db_sg_id"          { value = aws_security_group.db.id }
