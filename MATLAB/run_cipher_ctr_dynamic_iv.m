function x_encoded = run_cipher_ctr_dynamic_iv(u_mat, n_blks, N, K, Info, Frozen, key_bytes, iv_base)
% Crypto-coding bài báo:
%   AES-CTR(K, IV, counter i) -> subkey độ dài N
%   subkey(1:K)     XOR vào information bits (tập A)
%   subkey(K+1:N)   chèn vào frozen bits (tập A^c)
%   x = u * G_N, G_N = B_N F^{⊗n}
sKeySpec = javaObject('javax.crypto.spec.SecretKeySpec', key_bytes, 'AES');
aes_obj = javaMethod('getInstance', 'javax.crypto.Cipher', 'AES/CTR/NoPadding');
aes_obj.init(1, sKeySpec, javaObject('javax.crypto.spec.IvParameterSpec', iv_base));

x_encoded = zeros(n_blks, N);
req_bytes = ceil(N / 8);   % đúng N bit subkey, không lấy thừa N+64

for i = 1:n_blks
    keystream_bytes = aes_obj.update(zeros(1, req_bytes, 'int8'));
    bits_out = bytes_to_bits(typecast(keystream_bytes, 'uint8'));
    Mask = bits_out(1:K);
    Froz = bits_out(K+1:N);

    u_full = zeros(1, N);
    u_full(Info) = bitxor(u_mat(i, :), Mask);
    u_full(Frozen) = Froz;
    x_encoded(i, :) = polar_encode_GN(u_full);
end
end
