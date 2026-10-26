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

# --- VPC & Networking ---
resource "aws_vpc" "threat_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "threat-monitor-vpc-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.threat_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = { Name = "public-subnet-1-${var.environment}" }
}

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.threat_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true

  tags = { Name = "public-subnet-2-${var.environment}" }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.threat_vpc.id
  tags   = { Name = "threat-igw-${var.environment}" }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.threat_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = { Name = "public-route-table-${var.environment}" }
}

resource "aws_route_table_association" "pub_1" {
  subnet_id      = aws_subnet.public_1.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "pub_2" {
  subnet_id      = aws_subnet.public_2.id
  route_table_id = aws_route_table.public_rt.id
}

# --- Security Groups ---
resource "aws_security_group" "alb_sg" {
  name        = "threat-alb-sg-${var.environment}"
  description = "Allows inbound HTTP/HTTPS to ALB"
  vpc_id      = aws_vpc.threat_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ecs_sg" {
  name        = "threat-ecs-sg-${var.environment}"
  description = "Allows traffic from ALB to ECS tasks"
  vpc_id      = aws_vpc.threat_vpc.id

  ingress {
    from_port       = 0
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- CloudWatch Log Group ---
resource "aws_cloudwatch_log_group" "ecs_logs" {
  name              = "/ecs/cybersecurity-threat-monitor"
  retention_in_days = 30
}

# --- ECS Cluster ---
resource "aws_ecs_cluster" "cluster" {
  name = "threat-monitor-cluster-${var.environment}"
}

# --- RDS PostgreSQL Instance ---
resource "aws_db_subnet_group" "rds_subnets" {
  name       = "threat-db-subnets-${var.environment}"
  subnet_ids = [aws_subnet.public_1.id, aws_subnet.public_2.id]
}

resource "aws_security_group" "db_sg" {
  name   = "threat-db-sg-${var.environment}"
  vpc_id = aws_vpc.threat_vpc.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "postgres" {
  identifier             = "threat-soc-postgres"
  allocated_storage      = 20
  engine                 = "postgres"
  engine_version         = "15.4"
  instance_class         = "db.t4g.micro"
  db_name                = "threat_db"
  username               = "threat_admin"
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.rds_subnets.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  skip_final_snapshot    = true
}

# --- Application Load Balancer ---
resource "aws_lb" "alb" {
  name               = "threat-monitor-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_1.id, aws_subnet.public_2.id]
}

resource "aws_lb_target_group" "backend_tg" {
  name        = "threat-backend-tg"
  port        = 5000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.threat_vpc.id
  target_type = "ip"

  health_check {
    path                = "/health"
    matcher             = "200"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "listener" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend_tg.arn
  }
}
