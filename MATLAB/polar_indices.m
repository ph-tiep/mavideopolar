function [Info_Indices, Frozen_Indices] = polar_indices(N, K)
% Tập A / A^c đúng Polar: kênh tin cậy theo tham số Bhattacharyya trên BEC(0.5).
% Bài báo: "polar codes (N,K) classify N channels into reliable A and noisy A^c".
% (Không dùng bitrevorder(1:N) như MaHoa.m — đó không phải reliability Polar.)
if abs(log2(N) - round(log2(N))) > eps
    error('N phải là lũy thừa của 2.');
end
n = round(log2(N));
Z = zeros(N, 1);
Z(1) = 0.5;
for lev = 1:n
    gap = 2^(lev - 1);
    for j = gap:-1:1
        z = Z(j);
        Z(2*j-1) = 2*z - z*z;   % kênh xấu hơn
        Z(2*j)   = z*z;         % kênh tốt hơn
    end
end
[~, order] = sort(Z(:), 'ascend');
Info_Indices = order(1:K).';
Frozen_Indices = order(K+1:end).';
end
