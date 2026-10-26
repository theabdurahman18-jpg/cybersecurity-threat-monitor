output "alb_dns_name" {
  description = "Public DNS hostname of the Application Load Balancer"
  value       = aws_lb.alb.dns_name
}

output "vpc_id" {
  description = "VPC Identifier"
  value       = aws_vpc.threat_vpc.id
}

output "rds_endpoint" {
  description = "PostgreSQL RDS connection endpoint"
  value       = aws_db_instance.postgres.endpoint
}

output "ecs_cluster_name" {
  description = "Name of the created ECS Cluster"
  value       = aws_ecs_cluster.cluster.name
}
