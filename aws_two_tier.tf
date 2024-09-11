

# Create the VPC
resource "aws_vpc" "main" {
  cidr_block = var.VPCCIDR
  tags = {
    Application = var.StackName
    Network     = "MGMT"
    Name        = var.VPCName
  }
}

# IAM Role for Firewall
resource "aws_iam_role" "firewall_bootstrap_role" {
  name = "FirewallBootstrapRole2Tier"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action   = "sts:AssumeRole"
      }
    ]
  })
}

# IAM Role Policy for Firewall
resource "aws_iam_role_policy" "firewall_bootstrap_policy" {
  name = "FirewallBootstrapRolePolicy2Tier"
  role = aws_iam_role.firewall_bootstrap_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = "arn:aws:s3:::${var.MasterS3Bucket}"
      },
      {
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::${var.MasterS3Bucket}/*"
      }
    ]
  })
}

# IAM Instance Profile for Firewall
resource "aws_iam_instance_profile" "firewall_instance_profile" {
  name = "FirewallBootstrapInstanceProfile2Tier"
  role = aws_iam_role.firewall_bootstrap_role.name
}
# Fetch availability zones
data "aws_availability_zones" "available" {}

# Create Public Subnet
resource "aws_subnet" "new_public_subnet" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.PublicCIDR_Block
 availability_zone = "${var.aws_region}a" 
 tags = {
    Application = var.StackName
    Name        = "${var.StackName}NewPublicSubnet"
  }
}

# Create Web Subnet
resource "aws_subnet" "new_web_subnet" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.WebCIDR_Block
  availability_zone = "${var.aws_region}a"
  tags = {
    Application = var.StackName
    Name        = "${var.StackName}NewWebSubnet"
  }
}

# DHCP Options
resource "aws_vpc_dhcp_options" "dhcp_options" {
  domain_name         = "us-west-2.compute.internal"
  domain_name_servers = ["AmazonProvidedDNS"]
}

# Network ACL
resource "aws_network_acl" "network_acl" {
  vpc_id = aws_vpc.main.id
}

# Network ACL Ingress and Egress Rules
resource "aws_network_acl_rule" "ingress_rule" {
  network_acl_id = aws_network_acl.network_acl.id
  rule_number    = 100
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  egress         = false
}

resource "aws_network_acl_rule" "egress_rule" {
  network_acl_id = aws_network_acl.network_acl.id
  rule_number    = 100
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  egress         = true
}

# Route Tables
resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table" "web_route_table" {
  vpc_id = aws_vpc.main.id
}

# Network Interfaces
resource "aws_network_interface" "fw_management_network_interface" {
  subnet_id           = aws_subnet.new_public_subnet.id
  security_groups     = [aws_security_group.sg_wide_open.id]
  source_dest_check   = false
  private_ips         = ["10.0.0.99"]
}

resource "aws_network_interface" "fw_public_network_interface" {
  subnet_id           = aws_subnet.new_public_subnet.id
  security_groups     = [aws_security_group.sg_wide_open.id]
  source_dest_check   = false
  private_ips         = ["10.0.0.100"]
}

resource "aws_network_interface" "fw_private_network_interface" {
  subnet_id           = aws_subnet.new_web_subnet.id
  security_groups     = [aws_security_group.sg_wide_open.id]
  source_dest_check   = false
  private_ips         = ["10.0.1.11"]
}

resource "aws_network_interface" "wp_network_interface" {
  subnet_id           = aws_subnet.new_web_subnet.id
  security_groups     = [aws_security_group.sg_wide_open.id]
  source_dest_check   = false
  private_ips         = ["10.0.1.101"]
}

# Elastic IPs
resource "aws_eip" "public_elastic_ip" {

}

resource "aws_eip" "management_elastic_ip" {
  
}

# Internet Gateway
resource "aws_internet_gateway" "internet_gateway" {
  vpc_id = aws_vpc.main.id
  tags = {
    Application = var.StackName
    Network     = "MGMT"
    Name        = "${var.StackName}-InternetGateway"
  }
}

# Elastic IP Associations
resource "aws_eip_association" "fw_management_eip_association" {
  network_interface_id = aws_network_interface.fw_management_network_interface.id
  allocation_id        = aws_eip.management_elastic_ip.id
}

resource "aws_eip_association" "fw_public_eip_association" {
  network_interface_id = aws_network_interface.fw_public_network_interface.id
  allocation_id        = aws_eip.public_elastic_ip.id
}

# Route Table Associations
resource "aws_route_table_association" "public_subnet_route_table_association" {
  subnet_id      = aws_subnet.new_public_subnet.id
  route_table_id = aws_route_table.public_route_table.id
}

# Routes
resource "aws_route" "public_route" {
  route_table_id         = aws_route_table.public_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.internet_gateway.id
}

resource "aws_route" "web_route" {
  route_table_id         = aws_route_table.web_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.internet_gateway.id
}

# VPC DHCP Options Association
resource "aws_vpc_dhcp_options_association" "dhcp_options_association" {
  vpc_id          = aws_vpc.main.id
  dhcp_options_id = aws_vpc_dhcp_options.dhcp_options.id
}

# Security Group
resource "aws_security_group" "sg_wide_open" {
  name        = "sgWideOpen"
  description = "Wide open security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Firewall Instance
resource "aws_instance" "fw_instance" {
  ami                   = var.PANFWRegionMap[var.aws_region]
  instance_type         = "c5.xlarge"
  disable_api_termination = false
  instance_initiated_shutdown_behavior = "stop"
  ebs_optimized         = true
  key_name              = "gopikeypairtest"
  monitoring            = false

  iam_instance_profile  = aws_iam_instance_profile.firewall_instance_profile.name

  network_interface {
    device_index = 0
    network_interface_id = aws_network_interface.fw_management_network_interface.id
  }

  network_interface {
    device_index = 1
    network_interface_id = aws_network_interface.fw_public_network_interface.id
  }

  network_interface {
    device_index = 2
    network_interface_id = aws_network_interface.fw_private_network_interface.id
  }

  ebs_block_device {
    device_name           = "/dev/xvda"
    volume_type           = "gp2"
    delete_on_termination = true
    volume_size           = 60
  }

  user_data = base64encode(join("\n", [
    "vmseries-bootstrap-aws-s3bucket=${var.MasterS3Bucket}"
  ]))
}

/* # Web Instance
resource "aws_instance" "wp_web_instance" {
  ami                   = var.UbuntuRegionMap[var.aws_region]
  instance_type         = "c5.xlarge"
  disable_api_termination = false
  instance_initiated_shutdown_behavior = "stop"
  key_name              = "gopikeypairtest"
  monitoring            = false

  network_interface {
    device_index = 0
    network_interface_id = aws_network_interface.wp_network_interface.id
  }

  user_data = base64encode(join("\n", [
    "#!/bin/bash",
    "exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1",
    echo "export new_routers='${tolist(aws_network_interface.fw_private_network_interface.private_ips)[0]}'" >> /etc/dhcp/dhclient-enter-hooks.d/aws-default-route
    "ifdown eth0",
    "ifup eth0",
    "while true",
    "do",
    "  resp=$(curl -s -S -g --insecure \"https://${aws_eip.management_elastic_ip.public_ip}/api/?type=op&cmd=<show><chassis-ready></chassis-ready></show>&key=LUFRPT10VGJKTEV6a0R4L1JXd0ZmbmNvdUEwa25wMlU9d0N5d292d2FXNXBBeEFBUW5pV2xoZz09\")",
    "  echo $resp >> /tmp/pan.log",
    "  if [[ $resp == *\"[CDATA[yes\"* ]] ; then",
    "    break",
    "  fi",
    "  sleep 10s",
    "done",
    "apt-get update",
    "apt-get install -y apache2 wordpress"
  ]))
}
*/

# Check Firewall Readiness
resource "null_resource" "check_fw_ready" {
  triggers = {
    key = aws_instance.fw_instance.id
  }

  provisioner "local-exec" {
    command = "./check_fw.sh ${aws_eip.management_elastic_ip.public_ip}"
  }
}

# Outputs
output "firewall_management_url" {
  value = "https://${aws_eip.management_elastic_ip.public_ip}"
}

output "web_url" {
  value = "http://${aws_eip.public_elastic_ip.public_ip}"
}