# IaC scanner coverage-expansion progress

> Durable queue for the coverage-expansion grind. Each row: a resource_type
> the Evaluation Engine has controls for but the scanner does not yet map.
> Work highest-control-count first. For each: confirm config shape against
> the control source in ../nimbusguard-evaluation-engine + provider docs for
> defaults (never guess), add TF + CFN (AWS) / TF azurerm + Bicep (Azure)
> mappers, add tests, commit. Check off when committed.

## Done (pre-existing + this pass)
- [x] s3_bucket, security_group, rds_instance, kms_key, cloudtrail_trail, ebs_volume, iam_user, iam_role (pre-existing)
- [x] load_balancer (NG-AWS-ELB-001..007)
- [x] eks_cluster (NG-AWS-EKS-001..005)

## Deliberately deferred (account-wide aggregate / synthetic singletons — not a single IaC resource)
- accessanalyzer_status, azure_user, backup_account_settings, cloudwatch_metric_alarms, config_recorder, defender_settings, ec2_account_settings, emr_account_settings, entra_settings, guardduty_detector, iam_account_settings, iam_root_account, inspector_status, monitor_settings, network_settings, organizations_settings, s3_account_settings, securityhub_account

## Queue — AWS (38)
- [x] ec2_instance (6 controls) -- partial: ssm_managed/secrets_detected omitted (not knowable from IaC)
- [x] lambda_function (6 controls) -- TF also correlates function_url; resource_policy_allows_public/secrets_detected omitted
- [x] ecr_repository (4 controls) -- policy_allows_public omitted
- [x] cloudfront_distribution (3 of 4 controls) -- origin_access_controlled omitted (OAC shape not reliably derivable from IaC)
- [x] iam_password_policy (3 controls) -- Terraform only (no CFN resource)
- [x] dynamodb_table (3 controls)
- [x] efs_file_system (3 controls) -- policy_allows_anonymous_access omitted
- [x] elasticache_cluster (3 controls)
- [x] redshift_cluster (3 controls) -- publicly_accessible only when explicit
- [x] api_gateway_stage (3 controls) -- CFN omits waf_attached (separate association resource)
- [x] sagemaker_notebook_instance (3 controls)
- [x] ebs_snapshot -- SKIPPED: encrypted is inherited/runtime, publicly_shared not IaC-expressible
- [x] rds_snapshot -- SKIPPED: encrypted inherited/runtime, public sharing not a TF attribute
- [x] sns_topic (2 controls) -- policy_allows_public omitted
- [x] sqs_queue (2 controls) -- policy_allows_public omitted
- [x] secretsmanager_secret (2 controls) -- CFN omits rotation (separate resource)
- [x] acm_certificate (2 controls) -- days_to_expiry omitted (runtime)
- [x] waf_web_acl (2 controls) -- CFN omits logging (separate resource)
- [x] athena_workgroup (2 controls) -- TF/CFN enforce-default divergence documented
- [x] glue_data_catalog (2 controls)
- [x] emr_cluster -- SKIPPED: master_public_ip runtime/subnet-dependent, encryption via cross-resource security-config JSON
- [x] docdb_cluster (2 controls)
- [x] ami (1 control) -- public via cross-resource launch permission; TF only
- [x] ecs_cluster (1 control)
- [x] vpc (1 control) -- flow_logs via cross-resource aws_flow_log; TF only
- [x] subnet (1 control)
- [x] network_acl (1 control) -- TF only (CFN entries are separate NetworkAclEntry resources; empty list would false-PASS)
- [x] route53_hosted_zone (1 control) -- TF cross-resource query-log; CFN QueryLoggingConfig
- [x] kinesis_stream (1 control)
- [x] firehose_delivery_stream (1 control)
- [x] sfn_state_machine (1 control)
- [x] backup_vault (1 control)
- [x] cloudformation_stack -- SKIPPED: termination protection not an aws_cloudformation_stack attribute
- [x] dms_replication_instance (1 control) -- publicly_accessible default true
- [x] mq_broker (1 control)
- [x] codebuild_project (1 control)
- [x] route53_domain (1 control) -- TF only (no CFN registered-domain resource)
- [x] * -- N/A: the wildcard target is the vulnerability/side-channel control family, not an IaC-declarable resource type

## Queue — Azure (30, via Terraform azurerm_* + Bicep)
- [ ] network_security_group (16 controls)
- [ ] storage_account (14 controls)
- [ ] virtual_machine (13 controls)
- [x] sql_server (10 controls) -- azurerm (5 inline + 5 cross-resource children); Bicep inline-only (children are ARM sub-resources)
- [ ] aks_cluster (7 controls)
- [ ] app_service (7 controls)
- [x] key_vault (5 of 6 controls) -- azurerm + Bicep; access_policies (custom) omitted; logging via diagnostic-setting (TF only)
- [x] container_registry (5 controls) -- azurerm+Bicep
- [x] postgresql_server (4 controls) -- azurerm(flexible)+Bicep; ssl via require_secure_transport config (default ON)
- [x] mysql_server (4 controls) -- azurerm(flexible)+Bicep; ssl via require_secure_transport config (default ON)
- [x] cosmosdb_account (4 controls) -- azurerm + Bicep
- [ ] function_app (4 controls)
- [ ] recovery_services_vault (4 controls)
- [ ] application_gateway (3 controls)
- [ ] front_door (3 controls)
- [x] service_bus_namespace (3 controls) -- azurerm+Bicep; minimum_tls omitted when absent
- [x] redis_cache (3 controls) -- azurerm + Bicep; minimum_tls omitted when absent (version-ambiguous default)
- [x] managed_disk (2 of 3) -- public_network_access + network_access_policy; attached omitted (runtime state)
- [x] key_vault_key (2 controls) -- azurerm+Bicep
- [x] event_hub_namespace (2 controls) -- azurerm+Bicep
- [x] automation_account (2 controls) -- azurerm+Bicep
- [x] sql_database (2 controls) -- storage_account_type->API redundancy enum; ledger
- [x] api_management (1 of 2) -- public_network only; minimum_tls omitted (custom_properties mechanism)
- [ ] managed_identity (1 controls)
- [x] log_analytics_workspace (1 control) -- azurerm+Bicep; retention omitted when absent (no documented default)
- [x] subnet (1 control)
- [x] key_vault_secret (1 control) -- azurerm+Bicep
- [x] storage_container (1 control) -- container_access_type->API public_access enum
- [x] synapse_workspace (1 control) -- azurerm+Bicep
- [ ] * (1 controls)

