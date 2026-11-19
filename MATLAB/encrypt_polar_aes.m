function [cipher_u8, iv] = encrypt_polar_aes(plain_u8, key_bytes, N, K, Info, Frozen)
% JCM crypto-coding: AES-CTR subkey + Polar G_N = B_N F^{⊗n}.
% IV động = SHA-256(plaintext)[:16] — cùng cách MATLAB thí nghiệm bài báo
% (MaHoa.m). Nhờ đó 1 bit bản rõ đổi => IV đổi => NPCR/UACI ~ 99.61 / 33.46
% như Table III–IV JCM.
plain_u8 = uint8(plain_u8(:));
iv = generate_hash_iv(typecast(plain_u8, 'int8'));

bits = bytes_to_bits(plain_u8);
n_blocks = ceil(numel(bits) / K);
pad_len = n_blocks * K - numel(bits);
bits_pad = [bits, zeros(1, pad_len)];
u_mat = reshape(bits_pad, K, []).';

x_enc = run_cipher_ctr_dynamic_iv(u_mat, n_blocks, N, K, Info, Frozen, key_bytes, iv);
x_stream = reshape(x_enc.', 1, []);
cipher_u8 = bits_to_bytes(x_stream);
end
