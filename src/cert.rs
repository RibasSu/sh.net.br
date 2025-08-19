use anyhow::Result;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};
use std::fs;
use time::{Duration, OffsetDateTime};

pub fn generate_self_signed_cert(cert_path: &str, key_path: &str) -> Result<()> {
    // Criar diretório se não existir
    if let Some(parent) = std::path::Path::new(cert_path).parent() {
        fs::create_dir_all(parent)?;
    }

    // Configurar parâmetros do certificado
    let mut params = CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "*.sh.net.br".to_string(),
        "sh.net.br".to_string(),
    ]);

    // Configurar nomes alternativos
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".to_string()),
        SanType::DnsName("*.sh.net.br".to_string()),
        SanType::DnsName("sh.net.br".to_string()),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
    ];

    // Configurar informações do subject
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "SH.NET.BR Server");
    distinguished_name.push(DnType::OrganizationName, "SH.NET.BR");
    distinguished_name.push(DnType::CountryName, "BR");
    distinguished_name.push(DnType::LocalityName, "Brazil");
    
    params.distinguished_name = distinguished_name;

    // Configurar validade (1 ano)
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(365);

    // Gerar certificado
    let cert = Certificate::from_params(params)?;

    // Salvar certificado e chave privada
    let cert_pem = cert.serialize_pem()?;
    let key_pem = cert.serialize_private_key_pem();

    fs::write(cert_path, cert_pem)?;
    fs::write(key_path, key_pem)?;

    println!("Certificado TLS autoassinado gerado:");
    println!("  Certificado: {}", cert_path);
    println!("  Chave privada: {}", key_path);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_cert() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        let result = generate_self_signed_cert(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        );

        assert!(result.is_ok());
        assert!(cert_path.exists());
        assert!(key_path.exists());

        // Verificar que os arquivos não estão vazios
        let cert_content = fs::read_to_string(&cert_path).unwrap();
        let key_content = fs::read_to_string(&key_path).unwrap();

        assert!(cert_content.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert_content.contains("-----END CERTIFICATE-----"));
        assert!(key_content.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(key_content.contains("-----END PRIVATE KEY-----"));
    }
}
