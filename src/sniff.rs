pub fn sniff_http_host(data: &[u8]) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(data) {
        Ok(httparse::Status::Complete(_)) | Ok(httparse::Status::Partial) => {
            if let Some(host) = req.headers.iter().find(|h| h.name.eq_ignore_ascii_case("Host")) {
                let host_str = String::from_utf8(host.value.to_vec()).ok()?;
                if let Some(port_idx) = host_str.rfind(':') {
                    // Check if the part after ':' is a valid port number
                    if host_str[port_idx + 1..].parse::<u16>().is_ok() {
                         return Some(host_str[..port_idx].to_string());
                    }
                }
                return Some(host_str);
            }
        }
        Err(_) => {}
    }
    None
}

pub fn sniff_tls_sni(data: &[u8]) -> Option<String> {
    // Basic checks for TLS Client Hello
    if data.len() < 43 {
        return None;
    }

    // ContentType: Handshake (22)
    if data[0] != 0x16 {
        return None;
    }

    // Version: 3.x (TLS 1.0=0x0301, 1.1=0x0302, 1.2=0x0303, 1.3=0x0303 in record)
    if data[1] != 0x03 {
        return None;
    }

    let record_len = ((data[3] as usize) << 8) + data[4] as usize;
    if record_len + 5 > data.len() {
        return None; // Incomplete record
    }

    let handshake_type = data[5];
    if handshake_type != 0x01 { // ClientHello
        return None;
    }

    let mut cursor = 6 + 3; // Skip Record header + Handshake Type + Handshake Length (3 bytes)
    // Actually Handshake Length is 3 bytes.

    let handshake_len = ((data[6] as usize) << 16) + ((data[7] as usize) << 8) + data[8] as usize;
    if 5 + 4 + handshake_len > data.len() {
         // partial?
    }

    cursor += 2; // Client Version

    if cursor + 32 > data.len() { return None; }
    cursor += 32; // Random

    if cursor + 1 > data.len() { return None; }
    let session_id_len = data[cursor] as usize;
    cursor += 1;
    if cursor + session_id_len > data.len() { return None; }
    cursor += session_id_len;

    if cursor + 2 > data.len() { return None; }
    let cipher_suites_len = ((data[cursor] as usize) << 8) + data[cursor+1] as usize;
    cursor += 2;
    if cursor + cipher_suites_len > data.len() { return None; }
    cursor += cipher_suites_len;

    if cursor + 1 > data.len() { return None; }
    let compression_methods_len = data[cursor] as usize;
    cursor += 1;
    if cursor + compression_methods_len > data.len() { return None; }
    cursor += compression_methods_len;

    if cursor + 2 > data.len() { return None; }
    let extensions_len = ((data[cursor] as usize) << 8) + data[cursor+1] as usize;
    cursor += 2;

    let extensions_end = cursor + extensions_len;
    if extensions_end > data.len() { return None; }

    while cursor + 4 <= extensions_end {
        let ext_type = ((data[cursor] as usize) << 8) + data[cursor+1] as usize;
        let ext_len = ((data[cursor+2] as usize) << 8) + data[cursor+3] as usize;
        cursor += 4;

        if cursor + ext_len > extensions_end { break; }

        if ext_type == 0 { // server_name
            let mut sni_cursor = cursor;
            if sni_cursor + 2 > cursor + ext_len { return None; }
            let list_len = ((data[sni_cursor] as usize) << 8) + data[sni_cursor+1] as usize;
            sni_cursor += 2;

            if sni_cursor + list_len > cursor + ext_len { return None; }
            let list_end = sni_cursor + list_len;

            while sni_cursor + 3 <= list_end {
                let name_type = data[sni_cursor];
                let name_len = ((data[sni_cursor+1] as usize) << 8) + data[sni_cursor+2] as usize;
                sni_cursor += 3;

                if sni_cursor + name_len > list_end { break; }

                if name_type == 0 { // host_name
                    return String::from_utf8(data[sni_cursor..sni_cursor+name_len].to_vec()).ok();
                }
                sni_cursor += name_len;
            }
        }
        cursor += ext_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sniff_http_host() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(sniff_http_host(data), Some("example.com".to_string()));

        let data = b"GET / HTTP/1.1\r\nHost: google.com:80\r\n\r\n";
        assert_eq!(sniff_http_host(data), Some("google.com".to_string()));
    }

    #[test]
    fn test_sniff_tls_sni() {
        // Captured ClientHello for google.com (truncated for brevity but structure is valid)
        // This is a constructed minimal example or I can use a known byte sequence.
        // Let's rely on the logic being correct for now or write a helper to construct a packet.

        let mut packet = vec![
            0x16, 0x03, 0x01, 0x00, 0x00, // Record header (len patched later)
            0x01, 0x00, 0x00, 0x00, // Handshake header (len patched later)
            0x03, 0x03, // Version 1.2
        ];
        packet.extend([0u8; 32]); // Random
        packet.push(0); // Session ID len
        packet.extend([0x00, 0x02, 0x00, 0x2f]); // Cipher suites (len 2, TLS_RSA_WITH_AES_128_CBC_SHA)
        packet.push(1); // Compression len
        packet.push(0); // Compression null

        // Extensions
        let mut extensions = vec![];
        // SNI extension
        let hostname = b"example.com";
        let mut sni_ext = vec![
            0x00, 0x00, // Type SNI
            0x00, 0x00, // Len patched
        ];
        let mut sni_list = vec![
            0x00, 0x00, // List len patched
            0x00, // Type host_name
            0x00, 0x00, // Hostname len patched
        ];
        sni_list.extend(hostname);

        // Patch hostname len
        let hl = hostname.len();
        sni_list[3] = (hl >> 8) as u8;
        sni_list[4] = hl as u8;

        // Patch list len
        let ll = sni_list.len() - 2;
        sni_list[0] = (ll >> 8) as u8;
        sni_list[1] = ll as u8;

        sni_ext.extend(sni_list);

        // Patch ext len
        let el = sni_ext.len() - 4;
        sni_ext[2] = (el >> 8) as u8;
        sni_ext[3] = el as u8;

        extensions.extend(sni_ext);

        // Add Extensions len
        let exl = extensions.len();
        packet.push((exl >> 8) as u8);
        packet.push(exl as u8);
        packet.extend(extensions);

        // Patch Handshake len (starts at index 5, len is 3 bytes)
        let hsl = packet.len() - 9;
        packet[6] = (hsl >> 16) as u8;
        packet[7] = (hsl >> 8) as u8;
        packet[8] = hsl as u8;

        // Patch Record len
        let rl = packet.len() - 5;
        packet[3] = (rl >> 8) as u8;
        packet[4] = rl as u8;

        assert_eq!(sniff_tls_sni(&packet), Some("example.com".to_string()));
    }
}
