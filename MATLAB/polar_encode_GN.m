function x = polar_encode_GN(u)
% Mã hóa Polar đúng bài báo: x = u * G_N, G_N = B_N F^{⊗n}.
x = polar_encode(polar_bitrev(u));
end
