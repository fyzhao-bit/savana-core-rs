use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const MAX_MODEL_CONNECT_ADDRESSES_V2: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MeasuredModelNetworkErrorV2 {
    #[error("measured model connect addresses are invalid")]
    InvalidAddresses,
}

pub fn parse_measured_model_connect_addresses_v2(
    encoded: &[String],
    expected_port: u16,
) -> Result<Vec<SocketAddr>, MeasuredModelNetworkErrorV2> {
    if encoded.is_empty() || encoded.len() > MAX_MODEL_CONNECT_ADDRESSES_V2 {
        return Err(MeasuredModelNetworkErrorV2::InvalidAddresses);
    }
    let mut addresses = Vec::new();
    addresses
        .try_reserve_exact(encoded.len())
        .map_err(|_| MeasuredModelNetworkErrorV2::InvalidAddresses)?;
    for value in encoded {
        let address = value
            .parse::<SocketAddr>()
            .map_err(|_| MeasuredModelNetworkErrorV2::InvalidAddresses)?;
        if value != &address.to_string() {
            return Err(MeasuredModelNetworkErrorV2::InvalidAddresses);
        }
        addresses.push(address);
    }
    validate_measured_model_connect_addresses_v2(addresses, expected_port)
}

pub fn validate_measured_model_connect_addresses_v2(
    addresses: Vec<SocketAddr>,
    expected_port: u16,
) -> Result<Vec<SocketAddr>, MeasuredModelNetworkErrorV2> {
    if expected_port == 0
        || addresses.is_empty()
        || addresses.len() > MAX_MODEL_CONNECT_ADDRESSES_V2
        || addresses.windows(2).any(|pair| pair[0] >= pair[1])
        || addresses.iter().any(|address| {
            address.port() != expected_port || unsafe_destination_ip_v2(address.ip())
        })
    {
        return Err(MeasuredModelNetworkErrorV2::InvalidAddresses);
    }
    Ok(addresses)
}

pub fn measured_model_destination_ips_v2(addresses: &[SocketAddr]) -> Vec<IpAddr> {
    let mut ips = addresses
        .iter()
        .map(|address| address.ip())
        .collect::<Vec<_>>();
    ips.sort_unstable();
    ips.dedup();
    ips
}

fn unsafe_destination_ip_v2(ip: IpAddr) -> bool {
    ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(address) if address == Ipv4Addr::BROADCAST)
}

#[cfg(test)]
mod tests {
    use super::{
        measured_model_destination_ips_v2, parse_measured_model_connect_addresses_v2,
        validate_measured_model_connect_addresses_v2,
    };

    #[test]
    fn measured_addresses_are_bounded_canonical_sorted_and_safe() {
        let addresses = parse_measured_model_connect_addresses_v2(
            &["127.0.0.1:9443".to_owned(), "[2001:db8::1]:9443".to_owned()],
            9443,
        )
        .unwrap();
        assert_eq!(
            measured_model_destination_ips_v2(&addresses),
            vec![
                "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
                "2001:db8::1".parse::<std::net::IpAddr>().unwrap(),
            ]
        );
        assert!(validate_measured_model_connect_addresses_v2(addresses, 9443).is_ok());
    }
}
