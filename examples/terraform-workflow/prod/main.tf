# Demo only.
# Do not apply.
resource "aws_db_instance" "customer_demo" {
  publicly_accessible = true
}

resource "aws_db_instance" "internal_demo" {
  publicly_accessible = false
}
