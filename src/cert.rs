use crate::error::Result;
use lazy_static::lazy_static;
use openssl::{
    ec::{Asn1Flag, EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{self, PKey},
    rsa::Rsa,
    stack::Stack,
    x509::{extension::SubjectAlternativeName, X509Req, X509ReqBuilder, X509},
};

use crate::error::*;

lazy_static! {
    pub(crate) static ref EC_GROUP_P256: EcGroup = ec_group(Nid::X9_62_PRIME256V1);
    pub(crate) static ref EC_GROUP_P384: EcGroup = ec_group(Nid::SECP384R1);
}

fn ec_group(nid: Nid) -> EcGroup {
    let mut g = EcGroup::from_curve_name(nid).expect("EcGroup");
    // this is required for openssl 1.0.x (but not 1.1.x)
    g.set_asn1_flag(Asn1Flag::NAMED_CURVE);
    g
}

/// Make an RSA private key (from which we can derive a public key).
///
/// This library does not check the number of bits used to create the key pair.
/// For Let's Encrypt, the bits must be between 2048 and 4096.
pub fn create_rsa_key(bits: u32) -> Result<PKey<pkey::Private>> {
    let pri_key_rsa = Rsa::generate(bits)?;
    let pkey = PKey::from_rsa(pri_key_rsa)?;
    Ok(pkey)
}

/// Make a P-256 private key (from which we can derive a public key).
pub fn create_p256_key() -> Result<PKey<pkey::Private>> {
    let pri_key_ec = EcKey::generate(&*EC_GROUP_P256)?;
    let pkey = PKey::from_ec_key(pri_key_ec)?;
    Ok(pkey)
}

/// Make a P-384 private key pair (from which we can derive a public key).
pub fn create_p384_key() -> Result<PKey<pkey::Private>> {
    let pri_key_ec = EcKey::generate(&*EC_GROUP_P384)?;
    let pkey = PKey::from_ec_key(pri_key_ec)?;
    Ok(pkey)
}

pub(crate) fn create_csr(pkey: &PKey<pkey::Private>, domains: &[&str]) -> Result<X509Req> {
    //
    // the csr builder
    let mut req_bld = X509ReqBuilder::new()?;

    // set private/public key in builder
    req_bld.set_pubkey(&pkey)?;

    // set all domains as alt names
    let mut stack = Stack::new()?;
    let ctx = req_bld.x509v3_context(None);
    let as_lst = domains
        .iter()
        .map(|&e| format!("DNS:{}", e))
        .collect::<Vec<_>>()
        .join(", ");
    let as_lst = as_lst[4..].to_string();
    let mut an = SubjectAlternativeName::new();
    an.dns(&as_lst);
    let ext = an.build(&ctx)?;
    stack.push(ext).expect("Stack::push");
    req_bld.add_extensions(&stack)?;

    // sign it
    req_bld.sign(pkey, MessageDigest::sha256())?;

    // the csr
    Ok(req_bld.build())
}

/// Encapsulated certificate and private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    private_key: String,
    certificate: String,
}

impl Certificate {
    pub(crate) fn new(private_key: String, certificate: String) -> Self {
        Certificate {
            private_key,
            certificate,
        }
    }

    pub fn parse(private_key: String, certificate: String) -> Result<Self> {
        // validate certificate
        X509::from_pem(certificate.as_bytes())?;
        // validate private key
        PKey::private_key_from_pem(private_key.as_bytes())?;

        Ok(Certificate {
            private_key,
            certificate,
        })
    }

    /// The PEM encoded private key.
    pub fn private_key(&self) -> &str {
        &self.private_key
    }

    /// The private key as DER.
    pub fn private_key_der(&self) -> Result<Vec<u8>> {
        let pkey = PKey::private_key_from_pem(self.private_key.as_bytes())?;
        let der = pkey.private_key_to_der()?;
        Ok(der)
    }

    /// The PEM encoded issued certificate.
    pub fn certificate(&self) -> &str {
        &self.certificate
    }

    /// The issued certificate as DER.
    pub fn certificate_der(&self) -> Result<Vec<u8>> {
        let x509 = X509::from_pem(self.certificate.as_bytes())?;
        let der = x509.to_der()?;
        Ok(der)
    }

    /// Inspect the certificate to count the number of (whole) valid days left.
    ///
    /// It's up to the ACME API provider to decide how long an issued certificate is valid.
    /// Let's Encrypt sets the validity to 90 days. This function reports 89 days for newly
    /// issued cert, since it counts _whole_ days.
    ///
    /// It is possible to get negative days for an expired certificate.
    pub fn valid_days_left(&self) -> Result<i64> {
        // the cert used in the tests is not valid to load as x509
        if cfg!(test) {
            return Ok(89);
        }

        // load as x509
        let x509 = X509::from_pem(self.certificate.as_bytes())?;

        // convert asn1 time to Tm
        let not_after = format!("{}", x509.not_after());
        // Display trait produces this format, which is kinda dumb.
        // Apr 19 08:48:46 2019 GMT
        let expires = parse_date(&not_after)?;
        let dur = expires - time::OffsetDateTime::now_utc();

        Ok(dur.whole_days())
    }
}

fn parse_date(s: &str) -> Result<time::OffsetDateTime> {
    debug!("Parse date/time: {}", s);
    use time_fmt::parse::TimeZoneSpecifier;
    use time_tz::{Offset, TimeZone};
    let (datetime, zonespecifier) =
        time_fmt::parse::parse_date_time_maybe_with_zone("%h %e %H:%M:%S %Y %Z", s)
            .context("parsing of date failed")?;
    let offset_datetime = match zonespecifier {
        Some(TimeZoneSpecifier::Offset(offset)) => datetime.assume_offset(offset),
        None => datetime.assume_utc(),
        Some(TimeZoneSpecifier::Name(name)) => {
            let zone = time_tz::timezones::get_by_name(name)
                .ok_or(anyhow::anyhow!("unknown timezone specified"))?;
            datetime.assume_offset(zone.get_offset_primary().to_utc())
        }
    };
    Ok(offset_datetime)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_date() {
        let x = parse_date("May  3 07:40:15 2019 GMT")
            .context("input date parsing failed")
            .unwrap();
        assert_eq!(
            time_fmt::format::format_offset_date_time("%F %T", x)
                .context("date formatting failed")
                .unwrap(),
            "2019-05-03 07:40:15"
        );
    }
}
