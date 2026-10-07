# One customer managed key for the project's data at rest (SNS alerts,
# DynamoDB findings). A CMK, unlike an AWS managed key, gives us a key policy
# we control, automatic rotation, and CloudTrail visibility into every use.
# Cost: about $1/month while it exists.
resource "aws_kms_key" "project" {
  description             = "${var.project}: encrypts alerts and findings data"
  enable_key_rotation     = true
  deletion_window_in_days = 7 # shortest window; this is a disposable lab
}

resource "aws_kms_alias" "project" {
  name          = "alias/${var.project}"
  target_key_id = aws_kms_key.project.key_id
}
