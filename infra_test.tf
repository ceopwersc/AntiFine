resource "aws_security_group" "bad_sg" {
  name        = "allow_all_ssh"
  description = "Insecure open SSH"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "unencrypted_storage" {
  bucket = "prod-data-unencrypted-backup"
}

resource "aws_db_instance" "public_rds" {
  allocated_storage   = 20
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
}
