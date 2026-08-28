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
    resources = parse_source('''
resource "aws_lambda_function" "fn" {
  function_name = "my-function"
}
''')
    assert map_resources(resources) == []
    assert unmapped_resource_types(resources) == {"aws_lambda_function"}


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

resource "aws_lambda_function" "fn" {
  function_name = "my-function"
}
''')
    assert unmapped_resource_types(resources) == {"aws_lambda_function"}


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
