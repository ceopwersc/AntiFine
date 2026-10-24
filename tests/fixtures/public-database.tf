resource "aws_db_instance" "p0_fixture" {
  identifier          = "antifine-p0-fixture"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  publicly_accessible = true
}
