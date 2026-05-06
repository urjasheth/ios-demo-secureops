import Foundation

struct Secrets {
    // Intentionally hardcoded secrets to trigger Gitleaks and TruffleHog
    
    // Fake AWS Keys
    let awsAccessKeyId = "DUMMY_AWS_ACCESS_KEY"
    let awsSecretAccessKey = "DUMMY_AWS_SECRET_KEY"
    
    // Fake Stripe Key
    let stripeSecretKey = "sk_live_DUMMY_STRIPE_KEY"
    
    // Fake GCP Service Account Key segment
    let gcpPrivateKey = "DUMMY_GCP_PRIVATE_KEY_FOR_DEMO"
    
    // Fake GitHub Token
    let githubToken = "ghp_DUMMY_GITHUB_TOKEN_FOR_DEMO_REDACTED"
}
