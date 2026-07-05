output "vpc_id" {
  description = "ID of the VPC hosting agent runtimes"
  value       = aws_vpc.main.id
}

output "subnet_ids" {
  description = "List of private subnet IDs for agent runtime deployment"
  value       = aws_subnet.private[*].id
}

output "security_group_ids" {
  description = "Map of agent security group IDs"
  value = {
    orchestrator = aws_security_group.orchestrator.id
    scanner      = aws_security_group.scanner.id
    analysis     = aws_security_group.analysis.id
  }
}

output "orchestrator_security_group_id" {
  description = "Security group ID for the Orchestrator Agent"
  value       = aws_security_group.orchestrator.id
}

output "scanner_security_group_id" {
  description = "Security group ID for the Scanner Agent"
  value       = aws_security_group.scanner.id
}

output "analysis_security_group_id" {
  description = "Security group ID for the Analysis Agent"
  value       = aws_security_group.analysis.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}
