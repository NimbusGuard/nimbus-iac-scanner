"""nimbus-iac-scanner -- the E2.6 shift-left CLI: parses infrastructure-
as-code source (Terraform first; CloudFormation/Bicep a declared, not-
yet-built gap, see README.md) and calls nimbus_app's own
POST /iac/gate-check with the same, already-built, already-live-
verified resource shape a real runtime scan would use, so a
misconfiguration fails a CI pipeline with the exact same control ID it
would surface at runtime -- closing E2.6's own "listo cuando" criterion
literally."""

__version__ = "0.1.0"
