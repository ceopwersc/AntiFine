# Terraform workflow demonstration

These are synthetic, incomplete configurations for static scanning only. They have no provider setup, credentials, state, deployment scripts, or sufficient database configuration to deploy. Do not run Terraform apply.

Use **Scan → Try safe Terraform demo** for private imported copies, or select this project directory in the import picker. The packaged demo selects the two Terraform files; manual directory imports also show this Markdown file as unsupported coverage.

Each directory has a `main.tf` with one public and one private illustrative database. Inspect `aws_db_instance.customer_demo`, review the exact `true` → `false` diff, approve, apply and verify. Only the selected file/resource changes. A second finding in the other file remains open. Export evidence and reload to inspect persisted outcomes.

No Ollama setup or cloud account is required. Backups contain the private copy's original bytes. Changes to a selected server-local path edit that path rather than an imported copy.
