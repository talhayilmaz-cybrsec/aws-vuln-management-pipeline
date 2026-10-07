# -----------------------------------------------------------------------------
# Intentionally vulnerable scan target
#
# One small EC2 instance running Ubuntu 20.04 (past standard support) plus
# outdated Python packages, so Inspector produces real, recognizable findings.
#
# The instance itself is locked down: no inbound ports, no SSH key, IMDSv2
# only, encrypted disk. It is vulnerable on paper (package CVEs) but not
# reachable from the internet. Management is through SSM only.
#
# Remove it with `deploy_scan_target = false` once findings are captured.
# -----------------------------------------------------------------------------

locals {
  target_count = var.deploy_scan_target ? 1 : 0
}

data "aws_ssm_parameter" "target_ami" {
  name = var.target_ami_ssm_parameter
}

data "aws_vpc" "default" {
  default = true
}

# Pick only subnets in AZs where the instance type is offered
# (not every us-east-1 AZ supports every instance type).
data "aws_ec2_instance_type_offerings" "target" {
  location_type = "availability-zone"
  filter {
    name   = "instance-type"
    values = [var.target_instance_type]
  }
}

data "aws_subnets" "target" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
  filter {
    name   = "availability-zone"
    values = data.aws_ec2_instance_type_offerings.target.locations
  }
}

# --- Identity: SSM access only (needed for Inspector's agent-based scan) -----

data "aws_iam_policy_document" "ec2_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "target" {
  count              = local.target_count
  name               = "${var.project}-scan-target"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
}

resource "aws_iam_role_policy_attachment" "target_ssm" {
  count      = local.target_count
  role       = aws_iam_role.target[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "target" {
  count = local.target_count
  name  = "${var.project}-scan-target"
  role  = aws_iam_role.target[0].name
}

# --- Network: no inbound at all; outbound only for SSM (443) and apt (80) ----

resource "aws_security_group" "target" {
  count       = local.target_count
  name        = "${var.project}-scan-target"
  description = "Scan target: no inbound; outbound HTTPS for SSM, HTTP for apt"
  vpc_id      = data.aws_vpc.default.id
}

# Accepted risk (documented exception): the SSM agent must reach regional AWS
# endpoints over HTTPS. A production design would use VPC interface endpoints
# instead and remove internet egress entirely.
#trivy:ignore:AWS-0104
resource "aws_vpc_security_group_egress_rule" "https" {
  count             = local.target_count
  security_group_id = aws_security_group.target[0].id
  description       = "HTTPS to AWS endpoints (SSM, Inspector)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

# Accepted risk (documented exception): Ubuntu package mirrors serve over HTTP;
# packages are verified by apt's GPG signatures.
#trivy:ignore:AWS-0104
resource "aws_vpc_security_group_egress_rule" "http" {
  count             = local.target_count
  security_group_id = aws_security_group.target[0].id
  description       = "HTTP to Ubuntu package mirrors"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "0.0.0.0/0"
}

# --- Instance -----------------------------------------------------------------

resource "aws_instance" "target" {
  count                       = local.target_count
  ami                         = data.aws_ssm_parameter.target_ami.value
  instance_type               = var.target_instance_type
  subnet_id                   = data.aws_subnets.target.ids[0]
  vpc_security_group_ids      = [aws_security_group.target[0].id]
  iam_instance_profile        = aws_iam_instance_profile.target[0].name
  associate_public_ip_address = true # outbound path to SSM via the default VPC's internet gateway

  metadata_options {
    http_tokens   = "required" # IMDSv2 only: blocks SSRF-style credential theft
    http_endpoint = "enabled"
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
  }

  # Install deliberately outdated Python packages for language-package findings.
  user_data = <<-EOF
    #!/bin/bash
    apt-get update -y
    apt-get install -y python3-pip
    pip3 install --no-cache-dir "PyYAML==5.3.1" "requests==2.25.1" "Werkzeug==2.0.1"
  EOF

  user_data_replace_on_change = true

  # Asset context consumed by the risk engine (Phase 3): the same CVE matters
  # more on an internet-facing production asset than on an internal test box.
  # These tags SIMULATE the classification of a public web server so the
  # scoring can be demonstrated; the instance itself accepts no inbound traffic.
  tags = {
    Name                   = "${var.project}-scan-target"
    "vulnpipe:environment" = "demo"
    "vulnpipe:exposure"    = "internet"
    "vulnpipe:criticality" = "high"
  }
}
