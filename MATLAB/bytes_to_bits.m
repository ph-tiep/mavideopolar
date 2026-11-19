function bits = bytes_to_bits(u8)
% MSB-first, khớp reshape(dec2bin(u8,8).'-'0',1,[]) trong MaHoa.m
u8 = uint8(u8(:));
nb = numel(u8);
bits = zeros(1, nb * 8);
for k = 1:8
    bits(k:8:end) = double(bitget(u8, 9 - k));
end
end
