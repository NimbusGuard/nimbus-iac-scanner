# Reporte de trabajo nocturno — nimbus-iac-scanner: ampliar catálogo

**Tarea elegida (XL):** "IaC scanner: ampliar catálogo" — hacer el escáner IaC
"MUY robusto", expandiendo la cobertura de tipos de recurso en los 3 formatos
(Terraform, CloudFormation, Bicep), confirmando cada campo contra la fuente real
del control (evaluation-engine) + docs del proveedor, sin adivinar.

**Guardrails respetados durante toda la corrida:**
- ✅ Cero infraestructura billable / cero llamadas cloud (solo lecturas de docs
  públicas del proveedor vía WebFetch para confirmar defaults — no son llamadas cloud).
- ✅ Commits **locales, sin push** (17 commits por delante de origin/main).
- ✅ Cero decisiones de producto/cross-repo. Solo LEÍ la fuente de controles del
  engine y los collectors de nimbus_app como referencia; no toqué ni un archivo suyo.
- ✅ NO construí UI de nimbus_web (era cross-repo). El diseño de la sección UI queda
  para coordinar con la sesión de web (ver "Pendiente" abajo).

## Estado final

| Métrica | Valor |
|---|---|
| Commits locales (sin push) | **17** |
| Tipos mapeados en Terraform (aws_ + azurerm_) | **50 entradas** |
| Tipos mapeados en CloudFormation | **39 entradas** |
| Tipos mapeados en Bicep | **7 entradas** |
| Tests | **238 passing, 3 skipped** |
| Tipos del catálogo cerrados | **47** |
| Tipos abiertos (todos Azure) | **24** |

**Antes de esta corrida:** 8 tipos AWS (s3, security_group, rds, kms, cloudtrail,
ebs_volume, iam_user, iam_role) en TF+CFN, 2 Bicep parciales sin tests.

## Lo que se hizo

### AWS — **catálogo completo** (Terraform + CloudFormation)
Todos los tipos AWS con controles mapeables desde IaC, con tests, cada campo
confirmado contra la fuente del control + docs del proveedor:

- **Nuevos multi-control:** load_balancer, eks_cluster, dynamodb_table,
  ec2_instance, lambda_function, ecr_repository, efs_file_system,
  elasticache (replication_group + cluster), redshift_cluster, cloudfront_distribution
  (3/4 — ver omisiones), sagemaker_notebook_instance, docdb_cluster, waf_web_acl,
  athena_workgroup, api_gateway_stage (3/3).
- **Un control:** iam_password_policy (TF only), sns_topic, sqs_queue,
  secretsmanager_secret, acm_certificate, glue_data_catalog, kinesis_stream,
  firehose_delivery_stream, sfn_state_machine, backup_vault, dms_replication_instance,
  mq_broker, codebuild_project, ecs_cluster, subnet, ami (TF only), vpc (TF only),
  route53_hosted_zone, network_acl (TF only, custom entries), route53_domain (TF only).

**Omisiones deliberadas (doctrina: omitir antes que adivinar un veredicto):**
- `cloudfront_distribution.origin_access_controlled` — el patrón OAC moderno de TF
  declara un origen S3 sin bloque `s3_origin_config` ni `custom_origin_config`, así
  que "¿es un origen S3 con control de acceso?" no es derivable de forma confiable, y
  es un booleano all()-sobre-orígenes donde un origen mal clasificado voltea el
  veredicto → riesgo real de falso PASS. NOT_EVALUATED honesto.
- `api_gateway_stage.waf_attached` en **CFN** — la asociación WAF es un recurso
  separado (no hay vista cross-resource en CFN).
- `redshift_cluster.publicly_accessible` cuando ausente — default version-ambiguo del
  provider (histórico true, docs dicen false).

**Tipos AWS SALTADOS (con razón documentada en PROGRESS.md):**
- `ebs_snapshot` / `rds_snapshot` — `encrypted` se hereda del volumen/DB en runtime
  (no declarable); el sharing público no es un atributo IaC-expresable.
- `emr_cluster` — `master_public_ip` es runtime/subnet-dependiente; `encryption_at_rest`
  vive en un JSON de security-configuration cross-resource.
- `cloudformation_stack` — la protección de terminación no es un argumento de
  `aws_cloudformation_stack` ni una propiedad de un nested-stack CFN.
- `*` (target wildcard) — es la familia de controles de vulnerabilidad/side-channel,
  no un tipo de recurso declarable en IaC.

### Azure — patrón establecido + primer slice (azurerm + Bicep)
Antes de esta corrida **no existía ni un solo mapper azurerm** (Terraform) y los 2
mappers Bicep (NSG + storage) **no tenían tests**. Ahora:

- **Backfill de tests** para los 2 mappers Bicep pre-existentes (gap real cerrado).
- **redis_cache** (azurerm + Bicep) — primer mapper azurerm, patrón probado.
- **cosmosdb_account** (azurerm + Bicep) — 4 controles.
- **postgresql_server** + **mysql_server** (azurerm flexible + Bicep) — 4 c/u; helper
  compartido `_map_flexible_db`; `ssl_enforced` vía el parámetro
  `require_secure_transport` (recurso config cross-resource, default ON).
- **key_vault** (azurerm + Bicep) — 5/6 controles; helper reutilizable
  `_diagnostic_setting_has_enabled_log` para `logging_enabled` (sirve para futuros
  controles de logging Azure).

Cada default azurerm se confirmó **en vivo contra las docs del provider**
(vía el markdown fuente en GitHub — el registry es un SPA que WebFetch no renderiza).
Un default version-ambiguo que puede voltear un veredicto (ej. `redis.minimum_tls_version`,
que cambió 1.0→1.2 entre versiones) se **omite cuando el atributo está ausente**.

## Pendiente (24 tipos, todos Azure) — para continuar en sesión fresca

Ordenados por valor (nº de controles). **Cada uno necesita confirmar los defaults
azurerm/ARM en vivo** (WebFetch al markdown del provider) para no arriesgar falsos
veredictos — por eso conviene continuarlos con presupuesto de contexto fresco.

**Clasificación de complejidad (derivada esta noche):**
- **Flags simples (rápidos):** container_registry (5), service_bus_namespace (3),
  event_hub_namespace (2), automation_account (2), managed_identity (1),
  log_analytics_workspace (1), synapse_workspace (1).
- **Anidados/moderados:** virtual_machine (13), sql_server (10), aks_cluster (7),
  app_service (7), function_app (4), recovery_services_vault (4),
  application_gateway (3), front_door (3), managed_disk (3), sql_database (2),
  api_management (2), storage_container (1).
- **Custom (matching de reglas/listas — mayor cuidado):** network_security_group (16,
  reglas — como security_group/network_acl; el mapper Bicep NSG ya existe, falta el
  azurerm y expandir), storage_account (15 — varios custom: encryption,
  network_default_action, minimum_tls_version, account_replication_type; el Bicep
  cubre solo allow_blob_public_access hoy).
- **Sub-recursos (key/secret):** key_vault_key (2, rotation_policy/expiration),
  key_vault_secret (1, expiration).
- **N/A:** `*` (target wildcard, no IaC).

**Guía de continuación:** el patrón está probado y es mecánico:
1. `resource_mapping.py` (azurerm, firma `_map_x(key, body, all_resources)`, provider="azure").
2. `bicep_mapping.py` (firma `_map_x(key, resource)`, lee `resource["properties"]`).
3. Tests en `tests/test_resource_mapping.py` + `tests/test_bicep_mapping.py`.
4. Confirmar cada control en `../nimbusguard-evaluation-engine/.../controls/azure/`
   y cada default azurerm/ARM en vivo. Omitir cualquier campo cuyo default no se pueda
   confirmar (NOT_EVALUATED honesto > falso PASS).

## Items secundarios del plan (NO hechos — la tarea XL elegida fue "ampliar catálogo")

- **P2 supresiones inline** (`#nimbusguard:skip=CONTROL_ID`) — no hecho.
- **P3 salida SARIF** (`--format sarif`) — no hecho.
- **P5 doc de diseño de sección UI** — no hecho (requiere coordinar con la sesión de
  nimbus_web, que era cross-repo; el usuario dijo "cuando termines el motor, vayasen
  con web"). El motor no está 100% (falta el grueso Azure), así que este handoff
  todavía no aplica.

Todo el detalle por-tipo (razones de omisión, defaults confirmados) está en los
mensajes de commit y en `docs/PROGRESS.md`.
