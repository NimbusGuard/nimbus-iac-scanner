from nimbus_iac_scanner.resource_mapping import map_resources, unmapped_resource_types
from nimbus_iac_scanner.terraform_parser import parse_source


def test_s3_bucket_merges_a_referenced_public_access_block():
    resources = parse_source('''
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
  tags = {
    Environment = "prod"
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
''')
    mapped = map_resources(resources)
    assert len(mapped) == 1
    entry = mapped[0]
    assert entry["provider"] == "aws"
    assert entry["resource_type"] == "s3_bucket"
    assert entry["configuration"]["public_access_block"] == {
        "block_public_acls": False, "block_public_policy": False,
        "ignore_public_acls": False, "restrict_public_buckets": False,
    }
    assert entry["tags"] == {"Environment": "prod"}
    assert entry["identifier"] == "aws_s3_bucket.data"


def test_s3_bucket_public_access_block_referenced_by_literal_bucket_name():
    """Terraform allows referencing the bucket by its own literal name
    string, not just via a resource reference -- both forms must
    correlate correctly."""
    resources = parse_source('''
resource "aws_s3_bucket" "data" {
  bucket = "my-literal-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = "my-literal-bucket"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
''')
    mapped = map_resources(resources)
    entry = next(e for e in mapped if e["resource_type"] == "s3_bucket")
    assert entry["configuration"]["public_access_block"]["block_public_acls"] is True


def test_s3_bucket_with_no_public_access_block_omits_the_field_entirely():
    """No fabricated default either direction -- this is what makes the
    control correctly NOT_EVALUATED rather than a guessed PASS/FAIL."""
    resources = parse_source('''
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}
''')
    mapped = map_resources(resources)
    entry = mapped[0]
    assert "public_access_block" not in entry["configuration"]


def test_public_access_block_never_emitted_as_its_own_top_level_resource():
    resources = parse_source('''
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
''')
    mapped = map_resources(resources)
    assert len(mapped) == 1
    assert mapped[0]["resource_type"] == "s3_bucket"


def test_security_group_maps_a_single_ingress_block():
    resources = parse_source('''
resource "aws_security_group" "open_ssh" {
  name = "open-ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Team = "platform"
  }
}
''')
    mapped = map_resources(resources)
    assert len(mapped) == 1
    entry = mapped[0]
    assert entry["resource_type"] == "security_group"
    assert entry["configuration"]["ingress_rules"] == [
        {"protocol": "tcp", "from_port": 22, "to_port": 22, "sources": [{"type": "ipv4", "value": "0.0.0.0/0"}]}
    ]
    assert entry["tags"] == {"Team": "platform"}


def test_security_group_maps_multiple_ingress_blocks():
    resources = parse_source('''
resource "aws_security_group" "multi" {
  name = "multi-rule"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''')
    mapped = map_resources(resources)
    entry = mapped[0]
    assert len(entry["configuration"]["ingress_rules"]) == 2


def test_security_group_with_no_ingress_blocks_gets_an_empty_list():
    resources = parse_source('''
resource "aws_security_group" "egress_only" {
  name = "egress-only"
}
''')
    mapped = map_resources(resources)
    assert mapped[0]["configuration"]["ingress_rules"] == []


def test_unrecognized_resource_type_is_skipped_not_fabricated():
    # aws_lambda_layer_version has no Evaluation Engine control -> never mapped.
    resources = parse_source('''
resource "aws_lambda_layer_version" "lyr" {
  layer_name = "my-layer"
}
''')
    assert map_resources(resources) == []
    assert unmapped_resource_types(resources) == {"aws_lambda_layer_version"}


def test_unmapped_resource_types_excludes_recognized_and_consumed_only_types():
    resources = parse_source('''
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_lambda_layer_version" "lyr" {
  layer_name = "my-layer"
}
''')
    assert unmapped_resource_types(resources) == {"aws_lambda_layer_version"}


# --------------------------------------------------------------------------
# RDS (NG-AWS-RDS-001/002)
# --------------------------------------------------------------------------


def test_rds_instance_maps_publicly_accessible_and_storage_encrypted():
    resources = parse_source('''
resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = false
  tags = {
    Team = "data"
  }
}
''')
    entry = map_resources(resources)[0]
    assert entry["provider"] == "aws"
    assert entry["resource_type"] == "rds_instance"
    assert entry["configuration"] == {"publicly_accessible": True, "storage_encrypted": False}
    assert entry["tags"] == {"Team": "data"}
    assert entry["identifier"] == "aws_db_instance.db"


def test_rds_instance_omitted_attributes_use_the_real_confirmed_terraform_default_of_false():
    resources = parse_source('''
resource "aws_db_instance" "db" {
  identifier = "my-db"
}
''')
    entry = map_resources(resources)[0]
    assert entry["configuration"] == {"publicly_accessible": False, "storage_encrypted": False}


# --------------------------------------------------------------------------
# KMS key rotation (NG-AWS-KMS-001)
# --------------------------------------------------------------------------


def test_kms_key_maps_explicit_rotation_and_key_spec():
    resources = parse_source('''
resource "aws_kms_key" "k" {
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation       = true
}
''')
    entry = map_resources(resources)[0]
    assert entry["resource_type"] == "kms_key"
    assert entry["configuration"] == {
        "key_manager": "CUSTOMER", "key_spec": "SYMMETRIC_DEFAULT", "key_rotation_enabled": True,
    }


def test_kms_key_omitted_attributes_use_the_real_confirmed_terraform_defaults():
    resources = parse_source('''
resource "aws_kms_key" "k" {
  description = "a key with no explicit rotation setting"
}
''')
    entry = map_resources(resources)[0]
    assert entry["configuration"] == {
        "key_manager": "CUSTOMER", "key_spec": "SYMMETRIC_DEFAULT", "key_rotation_enabled": False,
    }


def test_kms_key_is_always_customer_managed_never_the_aws_managed_value():
    """A Terraform-declared key is always customer-managed -- a
    structural fact, not something to read off any attribute."""
    resources = parse_source('resource "aws_kms_key" "k" {}')
    entry = map_resources(resources)[0]
    assert entry["configuration"]["key_manager"] == "CUSTOMER"


# --------------------------------------------------------------------------
# CloudTrail logging (NG-AWS-CLOUDTRAIL-001)
# --------------------------------------------------------------------------


def test_cloudtrail_maps_explicit_enable_logging_false():
    resources = parse_source('''
resource "aws_cloudtrail" "audit" {
  name           = "audit-trail"
  enable_logging = false
}
''')
    entry = map_resources(resources)[0]
    assert entry["resource_type"] == "cloudtrail_trail"
    assert entry["configuration"] == {"is_logging": False}


def test_cloudtrail_omitted_enable_logging_uses_the_real_confirmed_default_of_true():
    resources = parse_source('resource "aws_cloudtrail" "audit" { name = "audit-trail" }')
    entry = map_resources(resources)[0]
    assert entry["configuration"] == {"is_logging": True}


# --------------------------------------------------------------------------
# EBS volume encryption -- no confirmed Terraform-level default, so an
# omitted attribute must be omitted from configuration entirely.
# --------------------------------------------------------------------------


def test_ebs_volume_maps_an_explicit_encrypted_value():
    resources = parse_source('''
resource "aws_ebs_volume" "vol" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = true
}
''')
    entry = map_resources(resources)[0]
    assert entry["resource_type"] == "ebs_volume"
    assert entry["configuration"] == {"encrypted": True}


def test_ebs_volume_with_no_encrypted_attribute_omits_the_field_entirely():
    resources = parse_source('''
resource "aws_ebs_volume" "vol" {
  availability_zone = "us-east-1a"
  size              = 10
}
''')
    entry = map_resources(resources)[0]
    assert entry["configuration"] == {}


# --------------------------------------------------------------------------
# Security group: the newer, decomposed aws_vpc_security_group_ingress_rule
# resource (AWS provider v5+), merged alongside the classic inline block.
# --------------------------------------------------------------------------


def test_security_group_merges_a_referenced_standalone_ingress_rule():
    resources = parse_source('''
resource "aws_security_group" "web" {
  name = "web-sg"
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.web.id
  ip_protocol        = "tcp"
  from_port          = 443
  to_port            = 443
  cidr_ipv4          = "0.0.0.0/0"
}
''')
    entry = map_resources(resources)[0]
    assert entry["configuration"]["ingress_rules"] == [
        {"protocol": "tcp", "from_port": 443, "to_port": 443, "sources": [{"type": "ipv4", "value": "0.0.0.0/0"}]}
    ]


def test_security_group_combines_inline_block_and_standalone_rule_resource():
    resources = parse_source('''
resource "aws_security_group" "combo" {
  name = "combo-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.combo.id
  ip_protocol        = "tcp"
  from_port          = 443
  to_port            = 443
  cidr_ipv4          = "0.0.0.0/0"
}
''')
    entry = map_resources(resources)[0]
    assert len(entry["configuration"]["ingress_rules"]) == 2


def test_standalone_ingress_rule_referencing_an_unknown_security_group_is_skipped():
    resources = parse_source('''
resource "aws_security_group" "web" {
  name = "web-sg"
}

resource "aws_vpc_security_group_ingress_rule" "orphan" {
  security_group_id = "sg-0123456789"
  ip_protocol        = "tcp"
  from_port          = 22
  to_port            = 22
  cidr_ipv4          = "0.0.0.0/0"
}
''')
    entry = map_resources(resources)[0]
    assert entry["configuration"]["ingress_rules"] == []


def test_standalone_ingress_rule_never_emitted_as_its_own_resource():
    resources = parse_source('''
resource "aws_security_group" "web" {
  name = "web-sg"
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.web.id
  ip_protocol        = "tcp"
  from_port          = 443
  to_port            = 443
  cidr_ipv4          = "0.0.0.0/0"
}
''')
    mapped = map_resources(resources)
    assert len(mapped) == 1
    assert mapped[0]["resource_type"] == "security_group"


# --------------------------------------------------------------------------
# IAM admin-privilege detection (NG-AWS-IAM-001 users / NG-AWS-IAM-012 roles)
# --------------------------------------------------------------------------


def test_iam_role_with_no_policies_at_all_gets_empty_lists_not_omitted():
    """Unlike the S3/public-access-block case, Terraform IS the full
    source of truth for what's attached to a role it also declares --
    zero attachment/inline-policy resources really does mean [], never
    "unknown."""
    resources = parse_source('resource "aws_iam_role" "svc" {}')
    entry = map_resources(resources)[0]
    assert entry["resource_type"] == "iam_role"
    assert entry["configuration"] == {"attached_policies": [], "inline_policies": []}


def test_iam_role_correlates_an_attached_admin_policy_via_reference():
    resources = parse_source('''
resource "aws_iam_role" "svc" {
  name = "my-service-role"
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.svc.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
''')
    entry = map_resources(resources)[0]
    assert entry["configuration"]["attached_policies"] == [{"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}]


def test_iam_role_correlates_an_attached_policy_via_literal_role_name():
    resources = parse_source('''
resource "aws_iam_role" "svc" {
  name = "literal-role-name"
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = "literal-role-name"
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
''')
    entry = map_resources(resources)[0]
    assert len(entry["configuration"]["attached_policies"]) == 1


def test_iam_user_correlates_its_own_attached_policy_not_a_different_users():
    resources = parse_source('''
resource "aws_iam_user" "alice" {
  name = "alice"
}

resource "aws_iam_user" "bob" {
  name = "bob"
}

resource "aws_iam_user_policy_attachment" "alice_admin" {
  user       = aws_iam_user.alice.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
''')
    mapped = {e["identifier"]: e for e in map_resources(resources)}
    assert mapped["aws_iam_user.alice"]["configuration"]["attached_policies"] == [
        {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}
    ]
    assert mapped["aws_iam_user.bob"]["configuration"]["attached_policies"] == []


def test_iam_role_parses_a_heredoc_inline_policy_document():
    resources = parse_source('''
resource "aws_iam_role" "svc" {
  name = "my-service-role"
}

resource "aws_iam_role_policy" "inline" {
  name = "inline-admin"
  role = aws_iam_role.svc.name

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
}
EOF
}
''')
    entry = map_resources(resources)[0]
    inline = entry["configuration"]["inline_policies"]
    assert len(inline) == 1
    assert inline[0]["policy_document"]["Statement"][0]["Action"] == "*"


def test_iam_role_parses_an_escaped_json_string_inline_policy():
    resources = parse_source('''
resource "aws_iam_role" "svc" {
  name = "my-service-role"
}

resource "aws_iam_role_policy" "inline" {
  name = "inline-admin"
  role = aws_iam_role.svc.name
  policy = "{\\"Version\\": \\"2012-10-17\\", \\"Statement\\": [{\\"Effect\\": \\"Allow\\"}]}"
}
''')
    entry = map_resources(resources)[0]
    inline = entry["configuration"]["inline_policies"]
    assert len(inline) == 1
    assert inline[0]["policy_document"]["Version"] == "2012-10-17"


def test_iam_role_silently_omits_an_unparseable_jsonencode_inline_policy():
    """jsonencode(...) is a real, common, idiomatic way to write this --
    and a static parser can never evaluate it. Must be omitted, never
    crash, never fabricated."""
    resources = parse_source('''
resource "aws_iam_role" "svc" {
  name = "my-service-role"
}

resource "aws_iam_role_policy" "inline" {
  name = "inline-admin"
  role = aws_iam_role.svc.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "*"
    }]
  })
}
''')
    entry = map_resources(resources)[0]
    assert entry["configuration"]["inline_policies"] == []


def test_iam_role_policy_attachment_never_emitted_as_its_own_top_level_resource():
    resources = parse_source('''
resource "aws_iam_role" "svc" {
  name = "my-service-role"
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.svc.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role_policy" "inline" {
  role   = aws_iam_role.svc.name
  policy = "{}"
}
''')
    mapped = map_resources(resources)
    assert len(mapped) == 1
    assert mapped[0]["resource_type"] == "iam_role"


# --- load_balancer (NG-AWS-ELB-001..007) ----------------------------------

def test_load_balancer_all_fields():
    resources = parse_source('''
resource "aws_lb" "public" {
  name                       = "app-lb"
  internal                   = false
  load_balancer_type         = "application"
  enable_deletion_protection = true

  access_logs {
    bucket  = "my-logs"
    enabled = true
  }

  tags = { Environment = "prod" }
}
''')
    entry = map_resources(resources)[0]
    assert entry["provider"] == "aws"
    assert entry["resource_type"] == "load_balancer"
    assert entry["configuration"] == {
        "scheme": "internet-facing",
        "type": "application",
        "deletion_protection_enabled": True,
        "access_logs_enabled": True,
    }
    assert entry["tags"] == {"Environment": "prod"}
    assert entry["identifier"] == "aws_lb.public"


def test_load_balancer_defaults_when_omitted():
    """internal absent -> internet-facing; type absent -> application;
    deletion protection absent -> false; no access_logs block -> false."""
    resources = parse_source('''
resource "aws_lb" "bare" {
  name = "bare-lb"
}
''')
    entry = map_resources(resources)[0]
    assert entry["configuration"] == {
        "scheme": "internet-facing",
        "type": "application",
        "deletion_protection_enabled": False,
        "access_logs_enabled": False,
    }


def test_load_balancer_internal_scheme_and_network_type():
    resources = parse_source('''
resource "aws_lb" "internal_nlb" {
  internal           = true
  load_balancer_type = "network"
}
''')
    cfg = map_resources(resources)[0]["configuration"]
    assert cfg["scheme"] == "internal"
    assert cfg["type"] == "network"


def test_load_balancer_access_logs_disabled_block():
    resources = parse_source('''
resource "aws_lb" "logs_off" {
  access_logs {
    bucket  = "b"
    enabled = false
  }
}
''')
    assert map_resources(resources)[0]["configuration"]["access_logs_enabled"] is False


def test_aws_alb_alias_maps_and_identifier_reflects_declared_type():
    resources = parse_source('''
resource "aws_alb" "legacy" {
  internal = false
}
''')
    entry = map_resources(resources)[0]
    assert entry["resource_type"] == "load_balancer"
    assert entry["identifier"] == "aws_alb.legacy"


# --- eks_cluster (NG-AWS-EKS-001..005) ------------------------------------

def test_eks_cluster_all_fields():
    resources = parse_source('''
resource "aws_eks_cluster" "main" {
  name    = "prod"
  version = "1.29"
  role_arn = "arn:aws:iam::1:role/eks"

  enabled_cluster_log_types = ["api", "audit", "authenticator"]

  vpc_config {
    endpoint_public_access  = false
    endpoint_private_access = true
    subnet_ids              = ["subnet-1"]
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = "arn:aws:kms:us-east-1:1:key/abc"
    }
  }
}
''')
    cfg = map_resources(resources)[0]["configuration"]
    assert cfg["enabled_log_types"] == ["api", "audit", "authenticator"]
    assert cfg["endpoint_public_access"] is False
    assert cfg["endpoint_private_access"] is True
    assert cfg["secrets_encryption_enabled"] is True
    assert cfg["version"] == "1.29"
    assert map_resources(resources)[0]["identifier"] == "aws_eks_cluster.main"


def test_eks_cluster_endpoint_defaults_and_no_logging_no_encryption():
    resources = parse_source('''
resource "aws_eks_cluster" "bare" {
  name     = "bare"
  role_arn = "arn:aws:iam::1:role/eks"
  vpc_config {
    subnet_ids = ["subnet-1"]
  }
}
''')
    cfg = map_resources(resources)[0]["configuration"]
    assert cfg["endpoint_public_access"] is True   # provider default
    assert cfg["endpoint_private_access"] is False  # provider default
    assert cfg["enabled_log_types"] == []
    assert cfg["secrets_encryption_enabled"] is False
    assert "version" not in cfg  # omitted when absent, never fabricated


def test_eks_cluster_encryption_config_without_secrets_is_not_secrets_encryption():
    resources = parse_source('''
resource "aws_eks_cluster" "other" {
  name     = "other"
  role_arn = "arn:aws:iam::1:role/eks"
  vpc_config { subnet_ids = ["subnet-1"] }
  encryption_config {
    resources = ["configmaps"]
    provider { key_arn = "arn:aws:kms:us-east-1:1:key/x" }
  }
}
''')
    assert map_resources(resources)[0]["configuration"]["secrets_encryption_enabled"] is False


# --- dynamodb_table (NG-AWS-DYNAMODB-001..003) ----------------------------

def test_dynamodb_table_all_fields_with_cmk():
    resources = parse_source('''
resource "aws_dynamodb_table" "t" {
  name                        = "orders"
  deletion_protection_enabled = true
  point_in_time_recovery { enabled = true }
  server_side_encryption {
    enabled     = true
    kms_key_arn = "arn:aws:kms:us-east-1:1:key/abc"
  }
}
''')
    cfg = map_resources(resources)[0]["configuration"]
    assert cfg == {"deletion_protection_enabled": True, "pitr_enabled": True, "encrypted_with_cmk": True}


def test_dynamodb_table_sse_without_cmk_is_not_cmk():
    """SSE enabled but no kms_key_arn = AWS-managed key, not a CMK."""
    resources = parse_source('''
resource "aws_dynamodb_table" "t" {
  name = "t"
  server_side_encryption { enabled = true }
}
''')
    assert map_resources(resources)[0]["configuration"]["encrypted_with_cmk"] is False


def test_dynamodb_table_defaults():
    resources = parse_source('''
resource "aws_dynamodb_table" "bare" { name = "bare" }
''')
    assert map_resources(resources)[0]["configuration"] == {
        "deletion_protection_enabled": False, "pitr_enabled": False, "encrypted_with_cmk": False,
    }


# --- ec2_instance (NG-AWS-EC2-010/011/023) --------------------------------

def test_ec2_instance_public_ip_and_imdsv2_and_monitoring():
    resources = parse_source('''
resource "aws_instance" "web" {
  ami                         = "ami-1"
  instance_type               = "t3.micro"
  monitoring                  = true
  associate_public_ip_address = true
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
}
''')
    cfg = map_resources(resources)[0]["configuration"]
    assert cfg["detailed_monitoring_enabled"] is True
    assert cfg["public_ip_address"] is True
    assert cfg["metadata_options"]["http_tokens"] == "required"
    assert map_resources(resources)[0]["identifier"] == "aws_instance.web"


def test_ec2_instance_no_public_ip_flag_and_no_metadata_block_defaults():
    """associate_public_ip_address absent -> omitted (subnet-dependent,
    unknowable); no metadata_options block -> http_tokens defaults 'optional'
    (IMDSv1 allowed, a real documented default); ssm_managed/secrets_detected
    never fabricated."""
    resources = parse_source('''
resource "aws_instance" "bare" {
  ami           = "ami-1"
  instance_type = "t3.micro"
}
''')
    cfg = map_resources(resources)[0]["configuration"]
    assert "public_ip_address" not in cfg
    assert cfg["metadata_options"] == {"http_tokens": "optional"}
    assert cfg["detailed_monitoring_enabled"] is False
    assert "ssm_managed" not in cfg
    assert "secrets_detected" not in cfg


def test_ec2_instance_public_ip_explicitly_false():
    resources = parse_source('''
resource "aws_instance" "private" {
  ami                         = "ami-1"
  instance_type               = "t3.micro"
  associate_public_ip_address = false
}
''')
    assert map_resources(resources)[0]["configuration"]["public_ip_address"] is False


# --- lambda_function (NG-AWS-AWSLAMBDA-002/003/004/005) --------------------

def test_lambda_function_all_knowable_fields_and_function_url_none():
    resources = parse_source('''
resource "aws_lambda_function" "fn" {
  function_name = "worker"
  runtime       = "python3.12"
  kms_key_arn   = "arn:aws:kms:us-east-1:1:key/abc"
  tracing_config { mode = "Active" }
}

resource "aws_lambda_function_url" "u" {
  function_name      = aws_lambda_function.fn.function_name
  authorization_type = "NONE"
}
''')
    entry = [e for e in map_resources(resources) if e["resource_type"] == "lambda_function"][0]
    cfg = entry["configuration"]
    assert cfg["runtime"] == "python3.12"
    assert cfg["env_encrypted_with_cmk"] is True
    assert cfg["xray_tracing_enabled"] is True
    assert cfg["function_url_auth_none"] is True
    assert "resource_policy_allows_public" not in cfg
    assert "secrets_detected" not in cfg
    assert entry["identifier"] == "aws_lambda_function.fn"


def test_lambda_function_defaults_and_no_url():
    resources = parse_source('''
resource "aws_lambda_function" "bare" {
  function_name = "bare"
  runtime       = "nodejs18.x"
}
''')
    cfg = map_resources(resources)[0]["configuration"]
    assert cfg["env_encrypted_with_cmk"] is False
    assert cfg["xray_tracing_enabled"] is False
    assert cfg["function_url_auth_none"] is False  # no URL resource -> no unauthenticated URL
    assert cfg["runtime"] == "nodejs18.x"


def test_lambda_function_url_with_iam_auth_is_not_auth_none():
    resources = parse_source('''
resource "aws_lambda_function" "fn" {
  function_name = "fn"
  runtime       = "python3.12"
}
resource "aws_lambda_function_url" "u" {
  function_name      = aws_lambda_function.fn.function_name
  authorization_type = "AWS_IAM"
}
''')
    entry = [e for e in map_resources(resources) if e["resource_type"] == "lambda_function"][0]
    assert entry["configuration"]["function_url_auth_none"] is False


def test_lambda_container_image_has_no_runtime_key():
    resources = parse_source('''
resource "aws_lambda_function" "img" {
  function_name = "img"
  package_type  = "Image"
  image_uri     = "1.dkr.ecr.us-east-1.amazonaws.com/app:latest"
}
''')
    assert "runtime" not in map_resources(resources)[0]["configuration"]


# --- ecr_repository (NG-AWS-ECR-001/002/004) ------------------------------

def test_ecr_repository_all_fields_with_lifecycle():
    resources = parse_source('''
resource "aws_ecr_repository" "app" {
  name                 = "app"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
}
resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy     = "{}"
}
''')
    entry = [e for e in map_resources(resources) if e["resource_type"] == "ecr_repository"][0]
    assert entry["configuration"] == {
        "scan_on_push_enabled": True, "tag_immutability_enabled": True, "lifecycle_policy_enabled": True,
    }
    assert "policy_allows_public" not in entry["configuration"]


def test_ecr_repository_defaults_no_lifecycle():
    resources = parse_source('''
resource "aws_ecr_repository" "bare" { name = "bare" }
''')
    assert map_resources(resources)[0]["configuration"] == {
        "scan_on_push_enabled": False, "tag_immutability_enabled": False, "lifecycle_policy_enabled": False,
    }


# --- efs_file_system (NG-AWS-EFS-001/002) ---------------------------------

def test_efs_file_system_encrypted_and_backup():
    resources = parse_source('''
resource "aws_efs_file_system" "fs" {
  encrypted = true
}
resource "aws_efs_backup_policy" "fs" {
  file_system_id = aws_efs_file_system.fs.id
  backup_policy { status = "ENABLED" }
}
''')
    entry = [e for e in map_resources(resources) if e["resource_type"] == "efs_file_system"][0]
    assert entry["configuration"] == {"encrypted": True, "backup_enabled": True}


def test_efs_file_system_defaults():
    resources = parse_source('resource "aws_efs_file_system" "bare" {}')
    assert map_resources(resources)[0]["configuration"] == {"encrypted": False, "backup_enabled": False}


# --- elasticache (NG-AWS-ELASTICACHE-001/002/003) -------------------------

def test_elasticache_replication_group_all_fields():
    resources = parse_source('''
resource "aws_elasticache_replication_group" "rg" {
  replication_group_id       = "rg"
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auto_minor_version_upgrade = false
}
''')
    assert map_resources(resources)[0]["configuration"] == {
        "at_rest_encryption_enabled": True, "transit_encryption_enabled": True, "auto_minor_version_upgrade": False,
    }


def test_elasticache_cache_cluster_only_auto_upgrade():
    resources = parse_source('''
resource "aws_elasticache_cluster" "c" {
  cluster_id = "c"
  engine     = "memcached"
}
''')
    cfg = map_resources(resources)[0]["configuration"]
    assert cfg == {"auto_minor_version_upgrade": True}  # encryption fields omitted (not on this resource)


# --- redshift_cluster (NG-AWS-REDSHIFT-001/002/003) -----------------------

def test_redshift_cluster_encrypted_logging_and_explicit_public():
    resources = parse_source('''
resource "aws_redshift_cluster" "c" {
  cluster_identifier  = "c"
  encrypted           = true
  publicly_accessible = false
  logging { enable = true }
}
''')
    assert map_resources(resources)[0]["configuration"] == {
        "encrypted": True, "audit_logging_enabled": True, "publicly_accessible": False,
    }


def test_redshift_cluster_omits_publicly_accessible_when_absent():
    """Version-ambiguous provider default -> omitted, not guessed."""
    resources = parse_source('''
resource "aws_redshift_cluster" "c" { cluster_identifier = "c" }
''')
    cfg = map_resources(resources)[0]["configuration"]
    assert cfg == {"encrypted": False, "audit_logging_enabled": False}
    assert "publicly_accessible" not in cfg


# --- iam_password_policy (NG-AWS-IAM-008/009/010) -------------------------

def test_iam_password_policy_all_fields():
    resources = parse_source('''
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_symbols                = true
  require_numbers               = true
  require_lowercase_characters  = true
  require_uppercase_characters  = true
  max_password_age              = 90
}
''')
    assert map_resources(resources)[0]["configuration"] == {
        "minimum_password_length": 14, "require_symbols": True, "require_numbers": True,
        "require_lowercase": True, "require_uppercase": True, "max_password_age_days": 90,
    }


def test_iam_password_policy_defaults():
    resources = parse_source('resource "aws_iam_account_password_policy" "weak" {}')
    assert map_resources(resources)[0]["configuration"] == {
        "minimum_password_length": 6, "require_symbols": False, "require_numbers": False,
        "require_lowercase": False, "require_uppercase": False, "max_password_age_days": 0,
    }


# --- sns_topic / sqs_queue -------------------------------------------------

def test_sns_topic_kms_encryption():
    assert map_resources(parse_source('''
resource "aws_sns_topic" "enc" { kms_master_key_id = "alias/aws/sns" }
'''))[0]["configuration"] == {"kms_encryption_enabled": True}
    assert map_resources(parse_source('resource "aws_sns_topic" "plain" {}'))[0]["configuration"] == {"kms_encryption_enabled": False}


def test_sqs_queue_encryption_either_mechanism():
    assert map_resources(parse_source('''
resource "aws_sqs_queue" "kms" { kms_master_key_id = "alias/aws/sqs" }
'''))[0]["configuration"] == {"encryption_enabled": True}
    assert map_resources(parse_source('''
resource "aws_sqs_queue" "sse" { sqs_managed_sse_enabled = true }
'''))[0]["configuration"] == {"encryption_enabled": True}
    assert map_resources(parse_source('resource "aws_sqs_queue" "plain" {}'))[0]["configuration"] == {"encryption_enabled": False}


# --- secretsmanager_secret (NG-AWS-SECRETSMANAGER-001/002) ----------------

def test_secretsmanager_secret_cmk_and_correlated_rotation():
    resources = parse_source('''
resource "aws_secretsmanager_secret" "s" { kms_key_id = "arn:aws:kms:...:key/abc" }
resource "aws_secretsmanager_secret_rotation" "s" {
  secret_id           = aws_secretsmanager_secret.s.id
  rotation_lambda_arn = "arn:aws:lambda:...:fn"
}
''')
    entry = [e for e in map_resources(resources) if e["resource_type"] == "secretsmanager_secret"][0]
    assert entry["configuration"] == {"encrypted_with_cmk": True, "rotation_enabled": True}


def test_secretsmanager_secret_defaults_no_rotation():
    resources = parse_source('resource "aws_secretsmanager_secret" "s" {}')
    assert map_resources(resources)[0]["configuration"] == {"encrypted_with_cmk": False, "rotation_enabled": False}


# --- acm_certificate (NG-AWS-ACM-002; 001 days_to_expiry omitted) ---------

def test_acm_certificate_transparency_default_enabled_when_absent():
    resources = parse_source('''
resource "aws_acm_certificate" "c" { domain_name = "example.com" }
''')
    cfg = map_resources(resources)[0]["configuration"]
    assert cfg == {"transparency_logging_enabled": True}
    assert "days_to_expiry" not in cfg  # runtime value, never guessed from IaC


def test_acm_certificate_transparency_explicitly_disabled():
    resources = parse_source('''
resource "aws_acm_certificate" "c" {
  domain_name = "example.com"
  options { certificate_transparency_logging_preference = "DISABLED" }
}
''')
    assert map_resources(resources)[0]["configuration"] == {"transparency_logging_enabled": False}


# --- cloudfront_distribution (NG-AWS-CLOUDFRONT-001/002/003; 004 omitted) --

def test_cloudfront_hardened():
    resources = parse_source('''
resource "aws_cloudfront_distribution" "cdn" {
  default_cache_behavior { viewer_protocol_policy = "redirect-to-https" }
  ordered_cache_behavior { viewer_protocol_policy = "https-only" }
  viewer_certificate { minimum_protocol_version = "TLSv1.2_2021" }
  logging_config { bucket = "logs.s3.amazonaws.com" }
}
''')
    cfg = map_resources(resources)[0]["configuration"]
    assert cfg == {"viewer_https_enforced": True, "minimum_tls_1_2": True, "access_logging_enabled": True}
    assert "origin_access_controlled" not in cfg  # deliberately NOT_EVALUATED


def test_cloudfront_insecure_allow_all_and_default_cert_and_no_logging():
    resources = parse_source('''
resource "aws_cloudfront_distribution" "cdn" {
  default_cache_behavior { viewer_protocol_policy = "allow-all" }
  viewer_certificate { cloudfront_default_certificate = true }
}
''')
    assert map_resources(resources)[0]["configuration"] == {
        "viewer_https_enforced": False, "minimum_tls_1_2": False, "access_logging_enabled": False,
    }


def test_cloudfront_ordered_behavior_allow_all_flips_https_enforced():
    resources = parse_source('''
resource "aws_cloudfront_distribution" "cdn" {
  default_cache_behavior { viewer_protocol_policy = "https-only" }
  ordered_cache_behavior { viewer_protocol_policy = "allow-all" }
  viewer_certificate { minimum_protocol_version = "TLSv1.1_2016" }
}
''')
    cfg = map_resources(resources)[0]["configuration"]
    assert cfg["viewer_https_enforced"] is False  # an ordered behavior is insecure
    assert cfg["minimum_tls_1_2"] is False  # TLSv1.1 < TLSv1.2


# --- sagemaker_notebook_instance (NG-AWS-SAGEMAKER-001/002/003) ------------

def test_sagemaker_hardened():
    resources = parse_source('''
resource "aws_sagemaker_notebook_instance" "nb" {
  name          = "nb"
  instance_type = "ml.t2.medium"
  root_access             = "Disabled"
  direct_internet_access  = "Disabled"
  kms_key_id              = "arn:aws:kms:...:key/abc"
}
''')
    assert map_resources(resources)[0]["configuration"] == {
        "root_access_enabled": False, "direct_internet_access_enabled": False, "encrypted_with_kms": True,
    }


def test_sagemaker_defaults_are_the_insecure_aws_defaults():
    resources = parse_source('''
resource "aws_sagemaker_notebook_instance" "nb" {
  name          = "nb"
  instance_type = "ml.t2.medium"
}
''')
    assert map_resources(resources)[0]["configuration"] == {
        "root_access_enabled": True, "direct_internet_access_enabled": True, "encrypted_with_kms": False,
    }


# --- docdb_cluster (NG-AWS-DOCDB-001/002) ---------------------------------

def test_docdb_cluster_explicit_and_default():
    assert map_resources(parse_source('''
resource "aws_docdb_cluster" "c" { storage_encrypted = true  backup_retention_period = 7 }
'''))[0]["configuration"] == {"storage_encrypted": True, "backup_retention_period": 7}
    assert map_resources(parse_source('resource "aws_docdb_cluster" "c" {}'))[0]["configuration"] == {
        "storage_encrypted": False, "backup_retention_period": 1,
    }


# --- waf_web_acl (NG-AWS-WAF-001/002) -------------------------------------

def test_waf_web_acl_with_rules_and_correlated_logging():
    resources = parse_source('''
resource "aws_wafv2_web_acl" "acl" {
  name  = "acl"
  scope = "REGIONAL"
  default_action { allow {} }
  rule { name = "r1" priority = 1 }
}
resource "aws_wafv2_web_acl_logging_configuration" "lc" {
  resource_arn            = aws_wafv2_web_acl.acl.arn
  log_destination_configs = ["arn:aws:logs:...:log-group:x"]
}
''')
    entry = [e for e in map_resources(resources) if e["resource_type"] == "waf_web_acl"][0]
    assert entry["configuration"] == {"has_rules": True, "logging_enabled": True}


def test_waf_web_acl_no_rules_no_logging():
    resources = parse_source('''
resource "aws_wafv2_web_acl" "acl" {
  name  = "acl"
  scope = "REGIONAL"
  default_action { allow {} }
}
''')
    assert map_resources(resources)[0]["configuration"] == {"has_rules": False, "logging_enabled": False}


# --- athena_workgroup (NG-AWS-ATHENA-001/002) -----------------------------

def test_athena_workgroup_encrypted_and_enforced():
    resources = parse_source('''
resource "aws_athena_workgroup" "wg" {
  name = "wg"
  configuration {
    enforce_workgroup_configuration = true
    result_configuration {
      encryption_configuration { encryption_option = "SSE_KMS" }
    }
  }
}
''')
    assert map_resources(resources)[0]["configuration"] == {
        "results_encryption_enabled": True, "enforce_workgroup_configuration": True,
    }


def test_athena_workgroup_no_config_block_uses_terraform_default_enforce_true():
    resources = parse_source('resource "aws_athena_workgroup" "wg" { name = "wg" }')
    assert map_resources(resources)[0]["configuration"] == {
        "results_encryption_enabled": False, "enforce_workgroup_configuration": True,
    }


# --- glue_data_catalog / kinesis / firehose / sfn / backup ----------------

def test_glue_data_catalog_both_encryptions():
    resources = parse_source('''
resource "aws_glue_data_catalog_encryption_settings" "s" {
  data_catalog_encryption_settings {
    encryption_at_rest { catalog_encryption_mode = "SSE-KMS" }
    connection_password_encryption { return_connection_password_encrypted = true }
  }
}
''')
    assert map_resources(resources)[0]["configuration"] == {
        "metadata_encryption_enabled": True, "connection_password_encryption_enabled": True,
    }


def test_glue_data_catalog_disabled_default():
    resources = parse_source('''
resource "aws_glue_data_catalog_encryption_settings" "s" {
  data_catalog_encryption_settings {
    encryption_at_rest { catalog_encryption_mode = "DISABLED" }
  }
}
''')
    assert map_resources(resources)[0]["configuration"] == {
        "metadata_encryption_enabled": False, "connection_password_encryption_enabled": False,
    }


def test_kinesis_stream_kms():
    assert map_resources(parse_source('''
resource "aws_kinesis_stream" "s" { name = "s" shard_count = 1 encryption_type = "KMS" }
'''))[0]["configuration"] == {"encryption_enabled": True}
    assert map_resources(parse_source('resource "aws_kinesis_stream" "s" { name = "s" shard_count = 1 }'))[0]["configuration"] == {"encryption_enabled": False}


def test_firehose_sse_block():
    assert map_resources(parse_source('''
resource "aws_kinesis_firehose_delivery_stream" "f" {
  name = "f" destination = "extended_s3"
  server_side_encryption { enabled = true }
}
'''))[0]["configuration"] == {"encryption_enabled": True}
    assert map_resources(parse_source('''
resource "aws_kinesis_firehose_delivery_stream" "f" { name = "f" destination = "extended_s3" }
'''))[0]["configuration"] == {"encryption_enabled": False}


def test_sfn_logging_level():
    assert map_resources(parse_source('''
resource "aws_sfn_state_machine" "m" {
  name = "m" role_arn = "arn:..." definition = "{}"
  logging_configuration { level = "ALL" }
}
'''))[0]["configuration"] == {"logging_enabled": True}
    assert map_resources(parse_source('''
resource "aws_sfn_state_machine" "m" {
  name = "m" role_arn = "arn:..." definition = "{}"
  logging_configuration { level = "OFF" }
}
'''))[0]["configuration"] == {"logging_enabled": False}
    assert map_resources(parse_source('''
resource "aws_sfn_state_machine" "m" { name = "m" role_arn = "arn:..." definition = "{}" }
'''))[0]["configuration"] == {"logging_enabled": False}


def test_backup_vault_cmk():
    assert map_resources(parse_source('''
resource "aws_backup_vault" "v" { name = "v" kms_key_arn = "arn:aws:kms:...:key/abc" }
'''))[0]["configuration"] == {"encrypted_with_cmk": True}
    assert map_resources(parse_source('resource "aws_backup_vault" "v" { name = "v" }'))[0]["configuration"] == {"encrypted_with_cmk": False}


# --- dms / mq / codebuild / ecs / subnet ----------------------------------

def test_dms_publicly_accessible_defaults_true():
    assert map_resources(parse_source('''
resource "aws_dms_replication_instance" "r" { replication_instance_id = "r" replication_instance_class = "dms.t3.micro" }
'''))[0]["configuration"] == {"publicly_accessible": True}
    assert map_resources(parse_source('''
resource "aws_dms_replication_instance" "r" { replication_instance_id = "r" replication_instance_class = "dms.t3.micro" publicly_accessible = false }
'''))[0]["configuration"] == {"publicly_accessible": False}


def test_mq_broker_publicly_accessible_defaults_false():
    assert map_resources(parse_source('''
resource "aws_mq_broker" "b" { broker_name = "b" engine_type = "ActiveMQ" engine_version = "5.17" host_instance_type = "mq.t3.micro" }
'''))[0]["configuration"] == {"publicly_accessible": False}


def test_codebuild_privileged_mode():
    assert map_resources(parse_source('''
resource "aws_codebuild_project" "p" {
  name = "p" service_role = "arn:..."
  environment { compute_type = "BUILD_GENERAL1_SMALL" image = "x" type = "LINUX_CONTAINER" privileged_mode = true }
  artifacts { type = "NO_ARTIFACTS" }
  source { type = "NO_SOURCE" }
}
'''))[0]["configuration"] == {"privileged_mode": True}


def test_ecs_cluster_container_insights():
    assert map_resources(parse_source('''
resource "aws_ecs_cluster" "c" {
  name = "c"
  setting { name = "containerInsights" value = "enabled" }
}
'''))[0]["configuration"] == {"container_insights_enabled": True}
    assert map_resources(parse_source('resource "aws_ecs_cluster" "c" { name = "c" }'))[0]["configuration"] == {"container_insights_enabled": False}


def test_subnet_map_public_ip():
    assert map_resources(parse_source('''
resource "aws_subnet" "s" { vpc_id = "vpc-1" cidr_block = "10.0.1.0/24" map_public_ip_on_launch = true }
'''))[0]["configuration"] == {"map_public_ip_on_launch": True}
    assert map_resources(parse_source('resource "aws_subnet" "s" { vpc_id = "vpc-1" cidr_block = "10.0.1.0/24" }'))[0]["configuration"] == {"map_public_ip_on_launch": False}


# --- ami / vpc / route53_hosted_zone (cross-resource) ---------------------

def test_ami_public_via_launch_permission_all():
    resources = parse_source('''
resource "aws_ami" "img" { name = "img" }
resource "aws_ami_launch_permission" "pub" {
  image_id = aws_ami.img.id
  group    = "all"
}
''')
    entry = [e for e in map_resources(resources) if e["resource_type"] == "ami"][0]
    assert entry["configuration"] == {"public": True}


def test_ami_private_by_default():
    resources = parse_source('resource "aws_ami" "img" { name = "img" }')
    assert map_resources(resources)[0]["configuration"] == {"public": False}


def test_vpc_flow_logs_via_flow_log_resource():
    resources = parse_source('''
resource "aws_vpc" "v" { cidr_block = "10.0.0.0/16" }
resource "aws_flow_log" "fl" {
  vpc_id          = aws_vpc.v.id
  traffic_type    = "ALL"
  log_destination = "arn:aws:logs:...:log-group:x"
}
''')
    entry = [e for e in map_resources(resources) if e["resource_type"] == "vpc"][0]
    assert entry["configuration"] == {"flow_logs_enabled": True}
    assert map_resources(parse_source('resource "aws_vpc" "v" { cidr_block = "10.0.0.0/16" }'))[0]["configuration"] == {"flow_logs_enabled": False}


def test_route53_hosted_zone_query_logging_via_query_log_resource():
    resources = parse_source('''
resource "aws_route53_zone" "z" { name = "example.com" }
resource "aws_route53_query_log" "ql" {
  zone_id                  = aws_route53_zone.z.zone_id
  cloudwatch_log_group_arn = "arn:aws:logs:...:log-group:x"
}
''')
    entry = [e for e in map_resources(resources) if e["resource_type"] == "route53_hosted_zone"][0]
    assert entry["configuration"] == {"query_logging_enabled": True}
    assert map_resources(parse_source('resource "aws_route53_zone" "z" { name = "example.com" }'))[0]["configuration"] == {"query_logging_enabled": False}


# --- api_gateway_stage (NG-AWS-APIGATEWAY-001/002/003) --------------------

def test_api_gateway_stage_all_three_via_cross_resources():
    resources = parse_source('''
resource "aws_api_gateway_stage" "prod" {
  rest_api_id          = "abc123"
  stage_name           = "prod"
  deployment_id        = "d1"
  xray_tracing_enabled = true
}
resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = "abc123"
  stage_name  = aws_api_gateway_stage.prod.stage_name
  method_path = "*/*"
  settings { logging_level = "INFO" }
}
resource "aws_wafv2_web_acl_association" "assoc" {
  resource_arn = aws_api_gateway_stage.prod.arn
  web_acl_arn  = "arn:aws:wafv2:...:webacl/x"
}
''')
    entry = [e for e in map_resources(resources) if e["resource_type"] == "api_gateway_stage"][0]
    assert entry["configuration"] == {
        "execution_logging_enabled": True, "xray_tracing_enabled": True, "waf_attached": True,
    }


def test_api_gateway_stage_defaults_all_false():
    resources = parse_source('''
resource "aws_api_gateway_stage" "prod" {
  rest_api_id   = "abc123"
  stage_name    = "prod"
  deployment_id = "d1"
}
''')
    assert map_resources(resources)[0]["configuration"] == {
        "execution_logging_enabled": False, "xray_tracing_enabled": False, "waf_attached": False,
    }


def test_api_gateway_stage_logging_off_is_not_enabled():
    resources = parse_source('''
resource "aws_api_gateway_stage" "prod" {
  rest_api_id   = "abc123"
  stage_name    = "prod"
  deployment_id = "d1"
}
resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = "abc123"
  stage_name  = aws_api_gateway_stage.prod.stage_name
  method_path = "*/*"
  settings { logging_level = "OFF" }
}
''')
    entry = [e for e in map_resources(resources) if e["resource_type"] == "api_gateway_stage"][0]
    assert entry["configuration"]["execution_logging_enabled"] is False


# --- network_acl (NG-AWS-EC2-024) -----------------------------------------

def test_network_acl_inline_ingress_normalizes_protocol_to_number():
    resources = parse_source('''
resource "aws_network_acl" "acl" {
  vpc_id = "vpc-1"
  ingress {
    rule_no    = 100
    action     = "allow"
    protocol   = "tcp"
    cidr_block = "0.0.0.0/0"
    from_port  = 22
    to_port    = 22
  }
  egress {
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}
''')
    entries = map_resources(resources)[0]["configuration"]["entries"]
    ingress = [e for e in entries if not e["egress"]][0]
    assert ingress == {
        "rule_number": 100, "egress": False, "protocol": "6", "rule_action": "allow",
        "cidr_block": "0.0.0.0/0", "from_port": 22, "to_port": 22,
    }
    egress = [e for e in entries if e["egress"]][0]
    assert egress["protocol"] == "-1" and egress["egress"] is True


def test_network_acl_merges_standalone_rules():
    resources = parse_source('''
resource "aws_network_acl" "acl" { vpc_id = "vpc-1" }
resource "aws_network_acl_rule" "r" {
  network_acl_id = aws_network_acl.acl.id
  rule_number    = 200
  egress         = false
  protocol       = "6"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 3389
  to_port        = 3389
}
''')
    entry = [e for e in map_resources(resources) if e["resource_type"] == "network_acl"][0]
    assert entry["configuration"]["entries"] == [{
        "rule_number": 200, "egress": False, "protocol": "6", "rule_action": "deny",
        "cidr_block": "0.0.0.0/0", "from_port": 3389, "to_port": 3389,
    }]
    # the standalone rule resource is never emitted on its own
    assert all(e["resource_type"] == "network_acl" for e in map_resources(resources))


def test_network_acl_empty_has_empty_entries():
    resources = parse_source('resource "aws_network_acl" "acl" { vpc_id = "vpc-1" }')
    assert map_resources(resources)[0]["configuration"]["entries"] == []


# --- route53_domain (NG-AWS-ROUTE53-002) ----------------------------------

def test_route53_domain_transfer_lock_default_true_and_explicit_false():
    assert map_resources(parse_source('''
resource "aws_route53domains_registered_domain" "d" { domain_name = "example.com" }
'''))[0]["configuration"] == {"transfer_lock_enabled": True}
    assert map_resources(parse_source('''
resource "aws_route53domains_registered_domain" "d" { domain_name = "example.com" transfer_lock = false }
'''))[0]["configuration"] == {"transfer_lock_enabled": False}


# --- azurerm redis_cache (NG-AZURE-REDIS-001/002/003) ---------------------

def test_azure_redis_hardened():
    resources = parse_source('''
resource "azurerm_redis_cache" "r" {
  name                          = "r"
  minimum_tls_version           = "1.2"
  non_ssl_port_enabled          = false
  public_network_access_enabled = false
}
''')
    entry = map_resources(resources)[0]
    assert entry["provider"] == "azure"
    assert entry["resource_type"] == "redis_cache"
    assert entry["configuration"] == {
        "non_ssl_port_enabled": False, "public_network_access_enabled": False, "minimum_tls_1_2": True,
    }


def test_azure_redis_defaults_omit_version_ambiguous_tls():
    resources = parse_source('resource "azurerm_redis_cache" "r" { name = "r" }')
    cfg = map_resources(resources)[0]["configuration"]
    # non_ssl default false, public-network default true (both stable azurerm defaults)
    assert cfg == {"non_ssl_port_enabled": False, "public_network_access_enabled": True}
    assert "minimum_tls_1_2" not in cfg  # version-ambiguous default -> NOT_EVALUATED


def test_azure_redis_legacy_enable_non_ssl_port_attr():
    resources = parse_source('''
resource "azurerm_redis_cache" "r" { name = "r" enable_non_ssl_port = true }
''')
    assert map_resources(resources)[0]["configuration"]["non_ssl_port_enabled"] is True


# --- azurerm cosmosdb_account (NG-AZURE-COSMOSDB-001..004) -----------------

def test_azure_cosmosdb_hardened():
    resources = parse_source('''
resource "azurerm_cosmosdb_account" "c" {
  name                          = "c"
  local_authentication_enabled  = false
  public_network_access_enabled = false
  key_vault_key_id              = "https://kv.vault.azure.net/keys/k"
  backup { type = "Continuous" }
}
''')
    assert map_resources(resources)[0]["configuration"] == {
        "network_access_restricted": True, "local_auth_disabled": True,
        "encrypted_with_cmk": True, "continuous_backup_enabled": True,
    }


def test_azure_cosmosdb_insecure_defaults():
    resources = parse_source('resource "azurerm_cosmosdb_account" "c" { name = "c" }')
    assert map_resources(resources)[0]["configuration"] == {
        "network_access_restricted": False, "local_auth_disabled": False,
        "encrypted_with_cmk": False, "continuous_backup_enabled": False,
    }


def test_azure_cosmosdb_vnet_filter_counts_as_restricted():
    resources = parse_source('''
resource "azurerm_cosmosdb_account" "c" { name = "c" is_virtual_network_filter_enabled = true }
''')
    assert map_resources(resources)[0]["configuration"]["network_access_restricted"] is True


# --- azurerm postgresql/mysql flexible server -----------------------------

def test_azure_postgresql_hardened_with_ssl_config():
    resources = parse_source('''
resource "azurerm_postgresql_flexible_server" "db" {
  name                          = "db"
  public_network_access_enabled = false
  geo_redundant_backup_enabled  = true
  backup_retention_days         = 30
}
resource "azurerm_postgresql_flexible_server_configuration" "ssl" {
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.db.id
  value     = "on"
}
''')
    entry = [e for e in map_resources(resources) if e["resource_type"] == "postgresql_server"][0]
    assert entry["configuration"] == {
        "ssl_enforced": True, "public_network_access_enabled": False,
        "geo_redundant_backup_enabled": True, "backup_retention_days": 30,
    }


def test_azure_postgresql_defaults_ssl_on_public_true_retention_7():
    resources = parse_source('resource "azurerm_postgresql_flexible_server" "db" { name = "db" }')
    assert map_resources(resources)[0]["configuration"] == {
        "ssl_enforced": True, "public_network_access_enabled": True,
        "geo_redundant_backup_enabled": False, "backup_retention_days": 7,
    }


def test_azure_postgresql_ssl_config_off_and_delegated_subnet_is_private():
    resources = parse_source('''
resource "azurerm_postgresql_flexible_server" "db" {
  name               = "db"
  delegated_subnet_id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/sn"
}
resource "azurerm_postgresql_flexible_server_configuration" "ssl" {
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.db.id
  value     = "off"
}
''')
    entry = [e for e in map_resources(resources) if e["resource_type"] == "postgresql_server"][0]
    assert entry["configuration"]["ssl_enforced"] is False
    assert entry["configuration"]["public_network_access_enabled"] is False  # VNet-integrated


def test_azure_mysql_flexible_maps_to_mysql_server():
    resources = parse_source('''
resource "azurerm_mysql_flexible_server" "db" { name = "db" geo_redundant_backup_enabled = true }
''')
    entry = map_resources(resources)[0]
    assert entry["resource_type"] == "mysql_server"
    assert entry["configuration"]["geo_redundant_backup_enabled"] is True
    assert entry["configuration"]["ssl_enforced"] is True  # default require_secure_transport ON
