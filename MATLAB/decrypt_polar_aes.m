function plain_u8 = decrypt_polar_aes(cipher_u8, num_plain_bytes, key_bytes, iv, N, K, Info)
cipher_u8 = uint8(cipher_u8(:));
n_blocks = ceil(num_plain_bytes * 8 / K);
need_bits = n_blocks * N;

bits = bytes_to_bits(cipher_u8);
if numel(bits) < need_bits
    error('Bản mã Polar thiếu bit (cần %d, có %d). Hãy giải từ Encrypted_Data.mat, không cắt từ AVI.', need_bits, numel(bits));
end

x_mat = reshape(bits(1:need_bits), N, []).';
u_mat = run_decipher_ctr_dynamic_iv(x_mat, n_blocks, N, K, Info, key_bytes, iv);

plain_bits = reshape(u_mat.', 1, []);
plain_bits = plain_bits(1:num_plain_bytes * 8);
plain_u8 = bits_to_bytes(plain_bits);
end
