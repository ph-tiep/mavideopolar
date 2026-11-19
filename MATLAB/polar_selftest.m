function polar_selftest(key_bytes, N, K, Info, Frozen)
rng(1);
plain = uint8(randi([0 255], 200, 1));
[c, iv] = encrypt_polar_aes(plain, key_bytes, N, K, Info, Frozen);
rec = decrypt_polar_aes(c, numel(plain), key_bytes, iv, N, K, Info);
if ~isequal(rec(:), plain(:))
    error('Self-test Polar+AES-CTR THẤT BẠI.');
end
if numel(c) < numel(plain)
    error('Self-test: ciphertext Polar ngắn hơn plaintext.');
end
fprintf('>> Self-test Polar+AES-CTR: OK (plain %d B -> cipher %d B)\n', numel(plain), numel(c));
end
