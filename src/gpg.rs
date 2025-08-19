use anyhow::{anyhow, Result};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub struct GpgManager {
    gpg_home: PathBuf,
    key_id: Option<String>,
}

impl GpgManager {
    pub fn new<P: AsRef<Path>>(gpg_home: P) -> Result<Self> {
        let gpg_home = gpg_home.as_ref().to_path_buf();
        
        // Criar diretório GPG se não existir
        fs::create_dir_all(&gpg_home)?;

        let mut manager = Self {
            gpg_home,
            key_id: None,
        };

        // Verificar se já existe uma chave ou criar uma nova
        manager.initialize_keys()?;

        Ok(manager)
    }

    fn initialize_keys(&mut self) -> Result<()> {
        // Verificar se já existem chaves
        let output = Command::new("gpg")
            .args(&[
                "--homedir",
                &self.gpg_home.to_string_lossy(),
                "--list-secret-keys",
                "--with-colons",
            ])
            .output()?;

        if output.status.success() && !output.stdout.is_empty() {
            // Extrair key ID da primeira chave encontrada
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.starts_with("sec:") {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() > 4 {
                        self.key_id = Some(parts[4].to_string());
                        println!("Usando chave GPG existente: {}", parts[4]);
                        return Ok(());
                    }
                }
            }
        }

        // Gerar nova chave se não existir
        self.generate_key()?;
        Ok(())
    }

    fn generate_key(&mut self) -> Result<()> {
        println!("Gerando nova chave GPG...");

        // Criar arquivo de configuração para geração da chave
        let key_config = r#"
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: SH.NET.BR Server
Name-Email: server@sh.net.br
Expire-Date: 1y
Passphrase: 
%commit
"#;

        let config_path = self.gpg_home.join("key_config.txt");
        fs::write(&config_path, key_config)?;

        // Gerar chave
        let output = Command::new("gpg")
            .args(&[
                "--homedir",
                &self.gpg_home.to_string_lossy(),
                "--batch",
                "--gen-key",
                &config_path.to_string_lossy(),
            ])
            .output()?;

        // Remover arquivo de configuração
        fs::remove_file(&config_path).ok();

        if !output.status.success() {
            return Err(anyhow!(
                "Falha ao gerar chave GPG: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Obter ID da chave gerada
        let output = Command::new("gpg")
            .args(&[
                "--homedir",
                &self.gpg_home.to_string_lossy(),
                "--list-secret-keys",
                "--with-colons",
            ])
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.starts_with("sec:") {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() > 4 {
                        self.key_id = Some(parts[4].to_string());
                        println!("Chave GPG gerada: {}", parts[4]);
                        break;
                    }
                }
            }
        }

        if self.key_id.is_none() {
            return Err(anyhow!("Falha ao obter ID da chave GPG gerada"));
        }

        Ok(())
    }

    pub fn sign_file<P: AsRef<Path>>(&self, file_path: P) -> Result<PathBuf> {
        let file_path = file_path.as_ref();
        let sig_path = file_path.with_extension("sh.sig");

        let key_id = self.key_id.as_ref()
            .ok_or_else(|| anyhow!("Nenhuma chave GPG disponível"))?;

        let output = Command::new("gpg")
            .args(&[
                "--homedir",
                &self.gpg_home.to_string_lossy(),
                "--armor",
                "--detach-sign",
                "--default-key",
                key_id,
                "--output",
                &sig_path.to_string_lossy(),
                &file_path.to_string_lossy(),
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!(
                "Falha ao assinar arquivo: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(sig_path)
    }

    pub fn verify_file<P: AsRef<Path>>(&self, file_path: P, sig_path: P) -> Result<bool> {
        let output = Command::new("gpg")
            .args(&[
                "--homedir",
                &self.gpg_home.to_string_lossy(),
                "--verify",
                &sig_path.as_ref().to_string_lossy(),
                &file_path.as_ref().to_string_lossy(),
            ])
            .output()?;

        Ok(output.status.success())
    }

    pub fn export_public_key(&self) -> Result<String> {
        let key_id = self.key_id.as_ref()
            .ok_or_else(|| anyhow!("Nenhuma chave GPG disponível"))?;

        let output = Command::new("gpg")
            .args(&[
                "--homedir",
                &self.gpg_home.to_string_lossy(),
                "--armor",
                "--export",
                key_id,
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!(
                "Falha ao exportar chave pública: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    pub fn import_public_key(&self, key_data: &str) -> Result<()> {
        let mut child = Command::new("gpg")
            .args(&[
                "--homedir",
                &self.gpg_home.to_string_lossy(),
                "--import",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        if let Some(stdin) = child.stdin.take() {
            use std::io::Write;
            let mut stdin = stdin;
            stdin.write_all(key_data.as_bytes())?;
        }

        let output = child.wait_with_output()?;

        if !output.status.success() {
            return Err(anyhow!(
                "Falha ao importar chave pública: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }

    pub fn list_keys(&self) -> Result<Vec<String>> {
        let output = Command::new("gpg")
            .args(&[
                "--homedir",
                &self.gpg_home.to_string_lossy(),
                "--list-keys",
                "--with-colons",
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!(
                "Falha ao listar chaves: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let mut keys = Vec::new();
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        for line in stdout.lines() {
            if line.starts_with("pub:") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() > 4 {
                    keys.push(parts[4].to_string());
                }
            }
        }

        Ok(keys)
    }

    pub fn get_key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_gpg_manager_creation() {
        let dir = tempdir().unwrap();
        let gpg_home = dir.path().join("gpg");
        
        // Este teste pode falhar se o GPG não estiver instalado
        if Command::new("gpg").arg("--version").output().is_ok() {
            let manager = GpgManager::new(&gpg_home);
            assert!(manager.is_ok());
        }
    }
}
