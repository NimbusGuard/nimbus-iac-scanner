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
