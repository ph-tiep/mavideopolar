function x = polar_encode(u)
% Polar encode: x = u * F^{⊗n} trên GF(2), O(N log N).
x = double(u(:).');
N = numel(x);
n = round(log2(N));
for s = 1:n
    span = 2^s;
    half = span / 2;
    for i = 1:span:N
        a = x(i:i+half-1);
        b = x(i+half:i+span-1);
        x(i:i+half-1) = mod(a + b, 2);
    end
end
end
