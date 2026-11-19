function u = polar_decode_GN(x)
% Nghịch đảo noiseless của G_N = B_N F^{⊗n}:
%   G^{-1} = F^{⊗n} B_N  (cả B_N và F^{⊗n} đều là involution).
% Bài báo dùng SC/SCL khi có nhiễu kênh; với file video (kênh sạch) bước này
% cho cùng û như SC khi frozen bits biết trước.
u = polar_bitrev(polar_encode(x));
end
