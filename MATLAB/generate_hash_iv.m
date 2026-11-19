function iv_bytes = generate_hash_iv(data_bytes)
% IV 16 byte = SHA-256(plaintext)[1:16] — đúng MaHoa.m / bài báo.
md = java.security.MessageDigest.getInstance('SHA-256');
hash = typecast(md.digest(data_bytes), 'int8');
iv_bytes = hash(1:16);
end
