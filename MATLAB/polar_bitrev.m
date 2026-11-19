function y = polar_bitrev(x)
% Bit-reversal permutation B_N trong công thức G_N = B_N F^{⊗n} (bài báo, eq. 6).
x = double(x(:).');
N = numel(x);
nb = round(log2(N));
idx = zeros(1, N);
for i = 0:N-1
    r = 0;
    t = i;
    for b = 1:nb
        r = r * 2 + bitand(t, 1);
        t = bitshift(t, -1);
    end
    idx(i + 1) = r + 1;
end
y = x(idx);
end
