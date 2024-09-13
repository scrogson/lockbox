/// TagEncoder for encoding tags using the TLV scheme inspired by DER encoding.
pub(crate) struct TagEncoder;

impl TagEncoder {
    const RESERVED: u8 = 1;
    const BYTE_LENGTH: usize = 256;
    const HALF_BYTE: usize = 128;

    /// Encodes a value using the TLV scheme inspired by DER encoding.
    pub fn encode(value: &[u8]) -> Vec<u8> {
        let value_len = value.len();

        if value_len >= Self::HALF_BYTE {
            let bitstring = Self::to_bitstring(value_len);
            Self::encode_with_bitstring(&bitstring, value)
        } else {
            // For value lengths less than 128, encode directly
            let mut encoded = Vec::with_capacity(2 + value_len);
            encoded.push(Self::RESERVED);
            encoded.push(value_len as u8); // Length byte
            encoded.extend_from_slice(value);
            encoded
        }
    }

    /// Handles encoding when the length of the value is 128 bytes or more.
    fn encode_with_bitstring(bitstring: &[u8], value: &[u8]) -> Vec<u8> {
        let bitstring_len = bitstring.len();
        let value_len = value.len();

        let mut encoded = Vec::with_capacity(2 + bitstring_len + value_len);
        encoded.push(Self::RESERVED);
        encoded.push((Self::HALF_BYTE + bitstring_len) as u8); // Length field with the most significant bit set
        encoded.extend_from_slice(bitstring); // Length bytes
        encoded.extend_from_slice(value); // Value bytes
        encoded
    }

    /// Converts a decimal value to its corresponding byte sequence.
    fn to_bitstring(decimal: usize) -> Vec<u8> {
        let mut result = Vec::new();
        let mut current = decimal;

        while current > 0 {
            result.push((current % Self::BYTE_LENGTH) as u8);
            current /= Self::BYTE_LENGTH;
        }

        result.reverse();
        result
    }
}

pub(crate) struct TagDecoder;

impl TagDecoder {
    const OFFSET: usize = 2;
    const BYTE_LENGTH: usize = 256;
    const HALF_BYTE: usize = 128;

    /// Decodes the message and extracts the tag and the remainder.
    pub fn decode(message: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        let length = Self::tag_length(message)?;

        if message.len() < length {
            return Err("Invalid message length");
        }

        // Split the message into TLV and remainder
        let (tlv, remainder) = message.split_at(length);

        // Extract the tag
        let tag = Self::tag(tlv)?;
        Ok((tag, remainder.to_vec()))
    }

    /// Calculates the length of the tag based on the TLV encoding.
    fn tag_length(message: &[u8]) -> Result<usize, &'static str> {
        if message.len() < 2 {
            return Err("Invalid message length");
        }

        let len = message[1] as usize;
        let rest = &message[2..];

        if len >= Self::HALF_BYTE {
            Ok(Self::OFFSET + len - Self::HALF_BYTE
                + Self::value_bytes(rest, len - Self::HALF_BYTE))
        } else {
            Ok(Self::OFFSET + len)
        }
    }

    /// Extracts the tag from the TLV encoded message.
    fn tag(tlv: &[u8]) -> Result<Vec<u8>, &'static str> {
        if tlv.len() < 2 {
            return Err("Invalid TLV format");
        }

        let len = tlv[1] as usize;
        let rest = &tlv[2..];

        if len >= Self::HALF_BYTE {
            let size = len - Self::HALF_BYTE;
            if rest.len() < size {
                return Err("Invalid TLV format");
            }

            Ok(rest[size..].to_vec())
        } else {
            Ok(rest.to_vec())
        }
    }

    /// Calculates the number of bytes needed to represent the value based on the list.
    fn value_bytes(list: &[u8], num_bytes: usize) -> usize {
        list.iter()
            .take(num_bytes)
            .fold(0, |acc, &value| acc * Self::BYTE_LENGTH + value as usize)
    }
}
