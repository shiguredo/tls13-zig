pub const DecodingError = error{
    InvalidType,
    InvalidLength,
    InvalidFormat,
    TooLarge,
    NotAllDecoded,
    UnsupportedFormat,
};

pub const EncodingError = error{
    InvalidArgument,
};

pub const CertificateError = error{
    UnsupportedSignatureAlgorithm,
    UnknownModulusLength,
    InvalidCACertificate,
};
