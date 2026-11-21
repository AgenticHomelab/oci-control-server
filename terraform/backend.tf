terraform {
  # Require native S3 conditional-write locks for both operator and Hermes.
  # Each runner must reinitialize its original backend before the next plan.
  backend "s3" {
    use_lockfile = true
  }
}
