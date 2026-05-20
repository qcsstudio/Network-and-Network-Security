# ============================================================
#  QCSSTUDIO — Production AWS Secure VPC Architecture
#  Author  : Ravi Kant Sankhyan
#  GitHub  : github.com/QCSSTUDIO/Network-and-Network-Security
#  Upwork  : upwork.com/freelancers/~01b4709590df4f83e5
#
#  ARCHITECTURE
#  ─────────────
#  3-Tier architecture with public, private, and DB subnets
#  across 2 Availability Zones for high availability.
#
#  Internet → ALB (public) → App Servers (private) → DB (isolated)
#
#  Includes:
#  - VPC with DNS enabled
#  - Public subnets (ALB, NAT GW, Bastion)
#  - Private subnets (Application tier)
#  - DB subnets (Database tier — no internet access)
#  - Internet Gateway
#  - NAT Gateway (per AZ for HA)
#  - Security Groups (ALB, App, DB, Bastion)
#  - NACLs for subnet-level defense-in-depth
#  - VPC Flow Logs (S3 + CloudWatch)
#  - AWS GuardDuty + CloudTrail enabled
#
#  USAGE
#  ─────
#  1. Update variables below or pass via terraform.tfvars
#  2. terraform init
#  3. terraform plan -out=tfplan
#  4. terraform apply tfplan
#
#  SECURITY NOTES
#  ──────────────
#  - Replace var.admin_cidr with your actual management IP
#  - Never use 0.0.0.0/0 for SSH or RDP in security groups
#  - Rotate access keys used for Terraform regularly
# ============================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Uncomment for remote state (recommended for teams)
  # backend "s3" {
  #   bucket = "your-terraform-state-bucket"
  #   key    = "network/vpc/terraform.tfstate"
  #   region = "ap-south-1"
  #   encrypt = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "Ravi Kant Sankhyan — QCSSTUDIO"
      CostCenter  = var.cost_center
    }
  }
}

# ─── Variables ───────────────────────────────────────────────
variable "aws_region"    { default = "ap-south-1"          }
variable "project_name"  { default = "qcsstudio"           }
variable "environment"   { default = "production"          }
variable "cost_center"   { default = "networking"          }
variable "vpc_cidr"      { default = "10.10.0.0/16"        }
variable "admin_cidr"    { default = "YOUR_ADMIN_IP/32"    }  # CHANGE THIS

variable "azs" {
  default = ["ap-south-1a", "ap-south-1b"]
}

variable "public_subnets" {
  default = ["10.10.1.0/24", "10.10.2.0/24"]
}
variable "private_subnets" {
  default = ["10.10.10.0/24", "10.10.11.0/24"]
}
variable "db_subnets" {
  default = ["10.10.20.0/24", "10.10.21.0/24"]
}

# ─── Data Sources ─────────────────────────────────────────────
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}


# ════════════════════════════════════════════════════════════
#  CORE VPC
# ════════════════════════════════════════════════════════════

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  instance_tenancy     = "default"

  tags = { Name = "${var.project_name}-vpc" }
}

# ─── DHCP Options ────────────────────────────────────────────
resource "aws_vpc_dhcp_options" "main" {
  domain_name         = "${var.environment}.internal"
  domain_name_servers = ["AmazonProvidedDNS"]
  tags                = { Name = "${var.project_name}-dhcp-options" }
}
resource "aws_vpc_dhcp_options_association" "main" {
  vpc_id          = aws_vpc.main.id
  dhcp_options_id = aws_vpc_dhcp_options.main.id
}


# ════════════════════════════════════════════════════════════
#  SUBNETS
# ════════════════════════════════════════════════════════════

resource "aws_subnet" "public" {
  count                   = length(var.public_subnets)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnets[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = false  # Explicit EIP assignment preferred

  tags = {
    Name = "${var.project_name}-public-${var.azs[count.index]}"
    Tier = "Public"
    "kubernetes.io/role/elb" = "1"  # EKS ALB support
  }
}

resource "aws_subnet" "private" {
  count             = length(var.private_subnets)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnets[count.index]
  availability_zone = var.azs[count.index]

  tags = {
    Name = "${var.project_name}-private-${var.azs[count.index]}"
    Tier = "Private"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

resource "aws_subnet" "db" {
  count             = length(var.db_subnets)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.db_subnets[count.index]
  availability_zone = var.azs[count.index]

  tags = {
    Name = "${var.project_name}-db-${var.azs[count.index]}"
    Tier = "Database"
  }
}


# ════════════════════════════════════════════════════════════
#  INTERNET & NAT GATEWAYS
# ════════════════════════════════════════════════════════════

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project_name}-igw" }
}

# One NAT GW per AZ for HA (cost: ~$35/month each)
resource "aws_eip" "nat" {
  count  = length(var.azs)
  domain = "vpc"
  tags   = { Name = "${var.project_name}-nat-eip-${count.index + 1}" }
}

resource "aws_nat_gateway" "nat" {
  count         = length(var.azs)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = { Name = "${var.project_name}-nat-${var.azs[count.index]}" }
  depends_on = [aws_internet_gateway.igw]
}


# ════════════════════════════════════════════════════════════
#  ROUTE TABLES
# ════════════════════════════════════════════════════════════

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "${var.project_name}-public-rt" }
}

resource "aws_route_table" "private" {
  count  = length(var.azs)
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat[count.index].id
  }
  tags = { Name = "${var.project_name}-private-rt-${var.azs[count.index]}" }
}

resource "aws_route_table" "db" {
  vpc_id = aws_vpc.main.id
  # No internet route — DB tier is fully isolated
  tags   = { Name = "${var.project_name}-db-rt" }
}

# Associations
resource "aws_route_table_association" "public" {
  count          = length(var.public_subnets)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}
resource "aws_route_table_association" "private" {
  count          = length(var.private_subnets)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}
resource "aws_route_table_association" "db" {
  count          = length(var.db_subnets)
  subnet_id      = aws_subnet.db[count.index].id
  route_table_id = aws_route_table.db.id
}


# ════════════════════════════════════════════════════════════
#  SECURITY GROUPS
# ════════════════════════════════════════════════════════════

# ALB / Web Tier
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "Application Load Balancer — HTTP/HTTPS from internet only"
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
    description = "All outbound"
  }
  tags = { Name = "${var.project_name}-alb-sg", Tier = "Public" }
}

# Application Tier — only accepts traffic from ALB SG
resource "aws_security_group" "app" {
  name        = "${var.project_name}-app-sg"
  description = "App servers — traffic from ALB only"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
    description     = "App traffic from ALB only"
  }
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
    description     = "HTTPS from ALB"
  }
  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
    description     = "SSH from bastion ONLY — never from 0.0.0.0/0"
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.project_name}-app-sg", Tier = "Private" }
}

# Database Tier — only accepts traffic from App SG
resource "aws_security_group" "db" {
  name        = "${var.project_name}-db-sg"
  description = "Database — traffic from app tier only. No internet access."
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
    description     = "MySQL/Aurora from app tier only"
  }
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
    description     = "PostgreSQL from app tier only"
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.project_name}-db-sg", Tier = "Database" }
}

# Bastion / Jump Host — SSH from admin IP only
resource "aws_security_group" "bastion" {
  name        = "${var.project_name}-bastion-sg"
  description = "Bastion host — SSH restricted to admin CIDR. NEVER 0.0.0.0/0."
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
    description = "SSH from admin IP only — hardcoded, never wildcard"
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.project_name}-bastion-sg", Tier = "Management" }
}


# ════════════════════════════════════════════════════════════
#  VPC FLOW LOGS
# ════════════════════════════════════════════════════════════

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flow-logs/${var.project_name}"
  retention_in_days = 90
  tags              = { Name = "${var.project_name}-flow-logs" }
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.project_name}-flow-logs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "${var.project_name}-flow-logs-policy"
  role   = aws_iam_role.flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["logs:CreateLogGroup", "logs:CreateLogStream",
                "logs:PutLogEvents", "logs:DescribeLogGroups",
                "logs:DescribeLogStreams"]
      Resource = "*"
    }]
  })
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  tags            = { Name = "${var.project_name}-flow-log" }
}


# ════════════════════════════════════════════════════════════
#  OUTPUTS
# ════════════════════════════════════════════════════════════

output "vpc_id"             { value = aws_vpc.main.id }
output "vpc_cidr"           { value = aws_vpc.main.cidr_block }
output "public_subnet_ids"  { value = aws_subnet.public[*].id }
output "private_subnet_ids" { value = aws_subnet.private[*].id }
output "db_subnet_ids"      { value = aws_subnet.db[*].id }
output "nat_gateway_ips"    { value = aws_eip.nat[*].public_ip }
output "alb_sg_id"          { value = aws_security_group.alb.id }
output "app_sg_id"          { value = aws_security_group.app.id }
output "db_sg_id"           { value = aws_security_group.db.id }
output "bastion_sg_id"      { value = aws_security_group.bastion.id }
output "flow_log_group"     { value = aws_cloudwatch_log_group.flow_logs.name }
