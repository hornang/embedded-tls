use crate::TlsError;
use crate::certificate::{ParsedCertificate, TbsCertificate};
use crate::config::{Certificate, TlsCipherSuite, TlsClock, TlsVerifier};
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::handshake::{
    certificate::{
        Certificate as OwnedCertificate, CertificateEntryRef, CertificateRef as ServerCertificate,
    },
    certificate_verify::CertificateVerifyRef,
};
use crate::parse_buffer::ParseError;
use core::marker::PhantomData;
use digest::Digest;
use heapless::Vec;

pub struct CertVerifier<CipherSuite, Clock, const CERT_SIZE: usize>
where
    Clock: TlsClock,
    CipherSuite: TlsCipherSuite,
{
    host: Option<heapless::String<64>>,
    certificate_transcript: Option<CipherSuite::Hash>,
    certificate: Option<OwnedCertificate<CERT_SIZE>>,
    _clock: PhantomData<Clock>,
}

impl<Cs, C, const CERT_SIZE: usize> Default for CertVerifier<Cs, C, CERT_SIZE>
where
    C: TlsClock,
    Cs: TlsCipherSuite,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<CipherSuite, Clock, const CERT_SIZE: usize> CertVerifier<CipherSuite, Clock, CERT_SIZE>
where
    Clock: TlsClock,
    CipherSuite: TlsCipherSuite,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            host: None,
            certificate_transcript: None,
            certificate: None,
            _clock: PhantomData,
        }
    }
}

impl<CipherSuite, Clock, const CERT_SIZE: usize> TlsVerifier<CipherSuite>
    for CertVerifier<CipherSuite, Clock, CERT_SIZE>
where
    CipherSuite: TlsCipherSuite,
    Clock: TlsClock,
{
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), TlsError> {
        self.host.replace(
            heapless::String::try_from(hostname).map_err(|()| TlsError::InsufficientSpace)?,
        );
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript: &CipherSuite::Hash,
        ca: &Option<Certificate>,
        cert: ServerCertificate,
    ) -> Result<(), TlsError> {
        verify_certificate(self.host.as_deref(), ca, &cert, Clock::now())?;
        self.certificate.replace(cert.try_into()?);
        self.certificate_transcript.replace(transcript.clone());
        Ok(())
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), TlsError> {
        let handshake_hash = unwrap!(self.certificate_transcript.take());
        let ctx_str = b"TLS 1.3, server CertificateVerify\x00";
        let mut msg: Vec<u8, 130> = Vec::new();
        msg.resize(64, 0x20).map_err(|()| TlsError::EncodeError)?;
        msg.extend_from_slice(ctx_str)
            .map_err(|()| TlsError::EncodeError)?;
        msg.extend_from_slice(&handshake_hash.finalize())
            .map_err(|()| TlsError::EncodeError)?;

        let certificate = unwrap!(self.certificate.as_ref()).try_into()?;
        verify_signature(&msg[..], &certificate, &verify)?;
        Ok(())
    }
}

fn verify_signature(
    message: &[u8],
    certificate: &ServerCertificate,
    verify: &CertificateVerifyRef,
) -> Result<(), TlsError> {
    let mut verified = false;
    if !certificate.entries.is_empty() {
        // TODO: Support intermediates...
        if let CertificateEntryRef::X509(certificate) = certificate.entries[0] {
            use der::Decode;

            let certificate = ParsedCertificate::<10>::from_der(certificate)
                .map_err(|_e| TlsError::DecodeError)?;

            let public_key = certificate
                .tbs_certificate
                .subject_public_key_info
                .public_key
                .as_bytes()
                .ok_or(TlsError::DecodeError)?;

            use p256::ecdsa::{VerifyingKey, signature::Verifier};

            let verifying_key =
                VerifyingKey::from_sec1_bytes(public_key).map_err(|_e| TlsError::DecodeError)?;
            let signature = p256::ecdsa::Signature::from_der(&verify.signature)
                .map_err(|_| TlsError::DecodeError)?;

            if verifying_key.verify(message, &signature).is_ok() {
                println!("Looks like it was OK!");
                verified = true;
            } else {
                println!("Not ok!");
            }
        }
    }
    if !verified {
        return Err(TlsError::InvalidSignature);
    }
    Ok(())
}


// TOOD: Replace with something from "der" crate
fn der_read_length(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    let first = *data.get(offset)?;
    if first < 0x80 {
        Some((first as usize, 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | (*data.get(offset + 1 + i)? as usize);
        }
        Some((len, 1 + num_bytes))
    }
}

// TOOD: Replace with something from "der" crate
fn get_tbs_certificate_portion(data: &[u8]) -> Option<&[u8]> {
    let mut offset = 0;

    /* // Outer SEQUENCE (Certificate)
    if *data.get(offset)? != 0x30 {
        return None;
    }
    let (cert_len, cert_len_len) = der_read_length(data, offset + 1)?;
    let cert_value_start = offset + 1 + cert_len_len;
    // No need to check cert_value_end

    offset = cert_value_start; */

    // tbsCertificate (SEQUENCE)
    if *data.get(offset)? != 0x30 {
        return None;
    }
    let (tbs_len, tbs_len_len) = der_read_length(data, offset + 1)?;
    let tbs_start = offset;
    let tbs_total_len = 1 + tbs_len_len + tbs_len;
    let tbs_end = tbs_start + tbs_total_len;

    data.get(tbs_start..tbs_end)
}

fn verify_certificate(
    verify_host: Option<&str>,
    ca: &Option<Certificate>,
    certificate: &ServerCertificate,
    now: Option<u64>,
) -> Result<(), TlsError> {
    let mut verified = false;
    let mut host_verified = false;

    if let Some(Certificate::X509(ca)) = ca {
        use der::Decode;

        let ca_certificate =
            ParsedCertificate::<10>::from_der(ca).map_err(|e| TlsError::DecodeError)?;

        if let CertificateEntryRef::X509(certificate) = certificate.entries[0] {
            let parsed_certificate = ParsedCertificate::<10>::from_der(certificate)
                .map_err(|_e| TlsError::DecodeError)?;

            let ca_public_key = ca_certificate
                .tbs_certificate
                .subject_public_key_info
                .public_key
                .as_bytes()
                .ok_or(TlsError::DecodeError)?;

            use p256::ecdsa::{VerifyingKey, signature::Verifier};

            let verifying_key =
                VerifyingKey::from_sec1_bytes(ca_public_key).map_err(|_e| TlsError::DecodeError)?;

            info!(
                "Signature alg: {:?}",
                parsed_certificate.signature_algorithm
            );

            let signature = p256::ecdsa::Signature::from_der(
                parsed_certificate
                    .signature
                    .as_bytes()
                    .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
            )
            .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;

            use der::asn1::SequenceRef;
            let seq = SequenceRef::from_der(certificate).map_err(|e| TlsError::DecodeError)?;
            let tbs_der = get_tbs_certificate_portion(seq.as_bytes()).ok_or(TlsError::DecodeError)?;

            if verifying_key.verify(&tbs_der, &signature).is_ok() {
                println!("Looks like it was OK!");
                verified = true;
            } else {
                println!("Not ok!");
            }
        }
    }

    if !verified {
        return Err(TlsError::InvalidCertificate);
    }

    if !host_verified && verify_host.is_some() {
        return Err(TlsError::InvalidCertificate);
    }
    Ok(())
}
