//! Small closed TPM command subset. No generic public command transport.
use crate::tpm_signature_v3::TpmSignatureErrorV3 as Error;
#[cfg(any(test, target_os = "linux"))]
use crate::tpm_signature_v3::{
    TpmSignatureEnvelopeV3, TpmSignatureRequestV3, TpmSigningBindingV3, TpmSigningPublicV3,
};
#[cfg(any(test, target_os = "linux"))]
use p256::ecdsa::Signature;
#[cfg(any(test, target_os = "linux"))]
use zeroize::Zeroizing;

#[cfg(any(test, target_os = "linux"))]
pub(crate) const MAX_RESPONSE: usize = 4096;
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(n).ok_or(Error::Malformed)?;
        let result = self.bytes.get(self.offset..end).ok_or(Error::Malformed)?;
        self.offset = end;
        Ok(result)
    }
    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Malformed)
    }
    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    pub(crate) fn sized(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()?;
        self.take(n as usize)
    }
    pub(crate) fn end(&self) -> Result<(), Error> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }
}

// Private trait: no downstream crate can inject a software signer into the
// production Linux device constructor. Unit/emulator transports stay cfg(test).
#[cfg(any(test, target_os = "linux"))]
pub(crate) trait Transport {
    fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>, Error>;
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) struct Signer<T> {
    transport: T,
    binding: TpmSigningBindingV3,
    auth: Zeroizing<[u8; 32]>,
    usable: bool,
}
#[cfg(any(test, target_os = "linux"))]
impl<T: Transport> Signer<T> {
    pub(crate) fn open(
        transport: T,
        binding: TpmSigningBindingV3,
        auth: Zeroizing<[u8; 32]>,
    ) -> Result<Self, Error> {
        if *auth == [0; 32] {
            return Err(Error::Malformed);
        }
        let mut result = Self {
            transport,
            binding,
            auth,
            usable: true,
        };
        result.check_public()?;
        Ok(result)
    }
    fn check_public(&mut self) -> Result<(), Error> {
        let command = command(0x8001, 0x173, &self.binding.handle.to_be_bytes());
        let response = exchange_command(&mut self.transport, &command)?;
        let mut r = response_body(&response, 0x8001)?;
        let area = r.sized()?;
        let mut public = (area.len() as u16).to_be_bytes().to_vec();
        public.extend_from_slice(area);
        let public = TpmSigningPublicV3::from_tpm2b_public(&public)?;
        let name = r.sized()?;
        let qualified_name = r.sized()?;
        r.end()?;
        if public != self.binding.public
            || name != public.name()
            || qualified_name != self.binding.qualified_name
        {
            return Err(Error::BindingMismatch);
        }
        Ok(())
    }
    pub(crate) fn sign(
        &mut self,
        request: TpmSignatureRequestV3,
    ) -> Result<TpmSignatureEnvelopeV3, Error> {
        if !self.usable {
            return Err(Error::Unavailable);
        }
        if request.installation_id() != self.binding.installation
            || request.epoch() != self.binding.epoch
        {
            return Err(Error::BindingMismatch);
        }
        let result = self.sign_inner(request);
        if result.is_err() {
            self.usable = false;
        }
        result
    }
    fn sign_inner(
        &mut self,
        request: TpmSignatureRequestV3,
    ) -> Result<TpmSignatureEnvelopeV3, Error> {
        self.check_public()?;
        let session = self
            .binding
            .pcr
            .map(|p| crate::tpm_policy::start(&mut self.transport, p))
            .transpose()?;
        let result = self.sign_authorized(request, session);
        if result.is_err() {
            if let Some(handle) = session {
                crate::tpm_policy::flush(&mut self.transport, handle);
            }
        }
        result
    }
    fn sign_authorized(
        &mut self,
        request: TpmSignatureRequestV3,
        session: Option<u32>,
    ) -> Result<TpmSignatureEnvelopeV3, Error> {
        let digest = request.prehash(self.binding.public.key_id());
        let mut body = Zeroizing::new(Vec::with_capacity(128));
        body.extend_from_slice(&self.binding.handle.to_be_bytes());
        body.extend_from_slice(&41_u32.to_be_bytes()); // TPMS_AUTH_COMMAND with 32-byte auth
        body.extend_from_slice(&session.unwrap_or(0x4000_0009).to_be_bytes());
        body.extend_from_slice(&[0, 0, 0]); // empty nonce, no flags
        body.extend_from_slice(&32_u16.to_be_bytes());
        body.extend_from_slice(self.auth.as_ref());
        body.extend_from_slice(&32_u16.to_be_bytes());
        body.extend_from_slice(&digest);
        body.extend_from_slice(&[0, 0x18, 0, 0x0b]); // ECDSA, SHA256; digest already hashed once
        body.extend_from_slice(&[0x80, 0x24, 0x40, 0, 0, 7, 0, 0]); // null HASHCHECK ticket
        let command = Zeroizing::new(command(0x8002, 0x15d, &body));
        let response = exchange_command(&mut self.transport, &command)?;
        let mut r = response_body(&response, 0x8002)?;
        let n = r.u32()? as usize;
        let mut s = Reader::new(r.take(n)?);
        if s.u16()? != 0x18 || s.u16()? != 0x0b {
            return Err(Error::Malformed);
        }
        let mut bytes = [0; 64];
        for offset in [0, 32] {
            let scalar = s.sized()?;
            if scalar.is_empty() || scalar.len() > 32 {
                return Err(Error::Malformed);
            }
            bytes[offset + 32 - scalar.len()..offset + 32].copy_from_slice(scalar);
        }
        s.end()?;
        if session.is_some() {
            // PolicyPassword returns a new nonce, no HMAC, and a closed session.
            if r.sized()?.len() != 32 || r.take(1)? != [0] || !r.sized()?.is_empty() {
                return Err(Error::Malformed);
            }
        } else if r.take(5)? != [0, 0, 1, 0, 0] {
            return Err(Error::Malformed); // TPM_RS_PW
        }
        r.end()?;
        let signature = Signature::from_slice(&bytes).map_err(|_| Error::InvalidSignature)?;
        TpmSignatureEnvelopeV3::from_tpm_signature(request, &self.binding.public, signature)
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn exchange_command(
    transport: &mut impl Transport,
    command: &[u8],
) -> Result<Vec<u8>, Error> {
    // Only this exact TPM warning certifies that the command did not start.
    // Never retry an IO error, lost response, malformed frame or auth failure.
    const RETRY: [u8; 10] = [0x80, 1, 0, 0, 0, 10, 0, 0, 9, 0x22];
    for _ in 0..5 {
        let response = transport.exchange(command)?;
        if response != RETRY {
            return Ok(response);
        }
    }
    Err(Error::OperationFailed)
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn command(tag: u16, code: u32, body: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(10 + body.len());
    b.extend_from_slice(&tag.to_be_bytes());
    b.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    b.extend_from_slice(&code.to_be_bytes());
    b.extend_from_slice(body);
    b
}
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn response_body(bytes: &[u8], expected_tag: u16) -> Result<Reader<'_>, Error> {
    if bytes.len() < 10 || bytes.len() > MAX_RESPONSE {
        return Err(Error::Malformed);
    }
    let mut r = Reader::new(bytes);
    let tag = r.u16()?;
    let size = r.u32()? as usize;
    let code = r.u32()?;
    if code != 0 {
        return Err(Error::OperationFailed);
    }
    if size != bytes.len() || tag != expected_tag {
        return Err(Error::Malformed);
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_is_exact_bounded_and_never_used_for_ambiguous_errors() {
        struct Reply {
            calls: usize,
            response: Result<Vec<u8>, Error>,
        }
        impl Transport for Reply {
            fn exchange(&mut self, _: &[u8]) -> Result<Vec<u8>, Error> {
                self.calls += 1;
                self.response.clone()
            }
        }
        let retry = vec![0x80, 1, 0, 0, 0, 10, 0, 0, 9, 0x22];
        let mut t = Reply {
            calls: 0,
            response: Ok(retry.clone()),
        };
        assert!(exchange_command(&mut t, &[]).is_err());
        assert_eq!(t.calls, 5);
        let mut malformed = retry.clone();
        malformed.push(0);
        let mut auth_failure = retry.clone();
        auth_failure[9] = 0x21;
        let mut wrong_tag = retry;
        wrong_tag[1] = 2;
        for response in [
            Err(Error::OperationFailed),
            Ok(malformed),
            Ok(auth_failure),
            Ok(wrong_tag),
        ] {
            let mut t = Reply { calls: 0, response };
            let _ = exchange_command(&mut t, &[]);
            assert_eq!(t.calls, 1);
        }
    }

    #[test]
    fn oversized_and_malformed_response_headers_fail_closed() {
        for bytes in [
            vec![],
            vec![0; 10],
            vec![0; 4097],
            vec![0x80, 1, 0, 0, 0, 10, 0, 0, 0, 0, 0],
        ] {
            assert!(response_body(&bytes, 0x8001).is_err());
        }
    }
}
