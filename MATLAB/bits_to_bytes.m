function u8 = bits_to_bytes(bits)
% Ngược của bytes_to_bits (MSB-first).
bits = double(bits(:).');
n = floor(numel(bits) / 8) * 8;
b = reshape(bits(1:n), 8, []);
w = [128; 64; 32; 16; 8; 4; 2; 1];
u8 = uint8(w' * b);
u8 = u8(:);
end
