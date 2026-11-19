function u_mat = run_decipher_ctr_dynamic_iv(x_encoded, n_blks, N, K, Info, key_bytes, iv_base)
% Bài báo: tái tạo subkey AES-CTR -> Polar decode -> bỏ frozen subkey -> XOR info.
sKeySpec = javaObject('javax.crypto.spec.SecretKeySpec', key_bytes, 'AES');
aes_obj = javaMethod('getInstance', 'javax.crypto.Cipher', 'AES/CTR/NoPadding');
aes_obj.init(1, sKeySpec, javaObject('javax.crypto.spec.IvParameterSpec', iv_base));

u_mat = zeros(n_blks, K);
req_bytes = ceil(N / 8);

for i = 1:n_blks
    keystream_bytes = aes_obj.update(zeros(1, req_bytes, 'int8'));
    bits_out = bytes_to_bits(typecast(keystream_bytes, 'uint8'));
    Mask = bits_out(1:K);

    u_full = polar_decode_GN(x_encoded(i, :));
    u_mat(i, :) = bitxor(u_full(Info), Mask);
end
end
