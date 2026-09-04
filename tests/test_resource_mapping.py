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
