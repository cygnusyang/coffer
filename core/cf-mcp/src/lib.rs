pub mod mcp {
    use std::error::Error;

    /// Return a list of all secret names.
    pub fn list_secret_names() -> Result<Vec<String>, Box<dyn Error>> {
        Ok(vec![])
    }

    /// Return a list of all secrets (name and metadata).
    pub fn list_secrets() -> Result<Vec<(String, String)>, Box<dyn Error>> {
        Ok(vec![])
    }

    /// Return a list of all environments.
    pub fn list_environments() -> Result<Vec<String>, Box<dyn Error>> {
        Ok(vec![])
    }

    /// Create a new environment. For now a stub.
    pub fn create_environment(_name: &str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// Mount an environment to a path. Stub.
    pub fn mount_environment(_env: &str, _path: &str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// Inject environment variables into current process.
    pub fn inject_environment(_env: &str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// Run a command with a secret injected.
    pub fn run_with_secret(_secret: &str, _cmd: &str, _args: &[&str]) -> Result<i32, Box<dyn Error>> {
        Ok(0)
    }

    /// Grant a secret to an agent. Stub.
    pub fn grant_secret(_secret: &str, _agent: &str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// Revoke a secret from an agent. Stub.
    pub fn revoke_secret(_secret: &str, _agent: &str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// Rotate a secret. Stub.
    pub fn rotate_secret(_secret: &str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// Get secret metadata. Stub.
    pub fn get_secret_metadata(_secret: &str) -> Result<String, Box<dyn Error>> {
        Ok(String::new())
    }

    /// Audit secret usage. Stub.
    pub fn audit_secret_usage(_secret: &str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}
