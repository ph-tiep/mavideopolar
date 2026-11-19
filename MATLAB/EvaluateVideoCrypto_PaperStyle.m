close all; clear; clc;

% =========================================================================
% EvaluateVideoCrypto_PaperStyle.m
% -------------------------------------------------------------------------
% Đánh giá mã hóa VIDEO theo đúng bộ chỉ số bài báo Audio Encryption
% (Polar codes + AES-CTR crypto-coding), nhưng đối tượng là khung hình video.
%
% Chỉ số giữ nguyên nghĩa với âm thanh (8-bit):
%   - Entropy, Correlation, NSCR/UACI, PSNR
% Hình trực quan thay waveform/spectrogram bằng:
%   - Frame gốc vs frame mã hóa
%   - Histogram pixel
%   - Scatter tương quan pixel kề
%
% Cách chạy: đặt Dog.mp4 cùng thư mục, mở MATLAB, nhấn Run.
% =========================================================================

%% ===================== CẤU HÌNH =====================
inputVideoFile = 'Dog.mp4';
maxSide = 160;          % thu nhỏ frame để Polar chạy nhanh khi demo (đặt [] = giữ nguyên)
N = 1024;               % độ dài Polar code (giống bài audio)
R = 0.5;                % code rate
K = N * R;
sampleScatter = 5000;   % số điểm vẽ scatter

% Khóa cố định để tái lập kết quả (đổi nếu muốn)
KEY_FIXED = int8([10, -20, 30, -40, 50, -60, 70, -80, 90, -100, 110, -120, 15, -25, 35, -45]);

if ~isfile(inputVideoFile)
    error('Không tìm thấy "%s". Hãy để video cùng thư mục script.', inputVideoFile);
end

import javax.crypto.*; %#ok<JAPIMAIN>
import javax.crypto.spec.*; %#ok<JAPIMAIN>
import java.security.MessageDigest; %#ok<JAPIMAIN>

%% ===================== POLAR SETUP =====================
n_log = log2(N);
if abs(n_log - round(n_log)) > eps
    error('N phải là lũy thừa của 2.');
end
Gn = 1;
F = [1 0; 1 1];
for i = 1:n_log
    Gn = kron(Gn, F);
end
Reliability = bitrevorder(1:N);
Info_Indices = Reliability(N-K+1:end);
Frozen_Indices = Reliability(1:N-K);

fprintf('>> KEY: %s\n', reshape(dec2hex(typecast(KEY_FIXED, 'uint8'))', 1, []));
fprintf('>> Polar (N,K) = (%d,%d)\n', N, K);

%% ===================== ĐỌC 1 KHUNG HÌNH =====================
v = VideoReader(inputVideoFile);
orig_frame_full = readFrame(v);
orig_frame = orig_frame_full;

if ~isempty(maxSide)
    [H0, W0, ~] = size(orig_frame);
    scale = maxSide / max(H0, W0);
    if scale < 1
        orig_frame = imresize(orig_frame, scale);
        fprintf('>> Resize frame: %dx%d -> %dx%d (cho nhanh)\n', W0, H0, size(orig_frame,2), size(orig_frame,1));
    end
end

[H, W, C] = size(orig_frame);
plain_u8 = orig_frame(:);                 % column-major như MATLAB
num_pixels = numel(plain_u8);
fprintf('>> Frame phân tích: %dx%dx%d (%d bytes)\n', H, W, C, num_pixels);

%% ===================== MÃ HÓA FRAME GỐC (P1) =====================
fprintf('\n1. Đang mã hóa khung hình gốc (Polar + AES-CTR)...\n');
[C1_u8, iv1] = polar_aes_encrypt_bytes(plain_u8, N, K, Gn, Info_Indices, Frozen_Indices, KEY_FIXED);
enc_frame = reshape(C1_u8(1:num_pixels), H, W, C);

%% ===================== DIFFERENTIAL: LẬT 1 BIT (P2) =====================
fprintf('2. Đang mã hóa bản lật 1 bit (NSCR/UACI)...\n');
mod_frame = orig_frame;
mod_frame(1,1,1) = bitxor(mod_frame(1,1,1), uint8(1));
plain2_u8 = mod_frame(:);
[C2_u8, iv2] = polar_aes_encrypt_bytes(plain2_u8, N, K, Gn, Info_Indices, Frozen_Indices, KEY_FIXED);

%% ===================== GIẢI MÃ KIỂM TRA =====================
fprintf('3. Đang giải mã kiểm tra khôi phục...\n');
dec_u8 = polar_aes_decrypt_bytes(C1_u8, num_pixels, N, K, Gn, Info_Indices, KEY_FIXED, iv1);
dec_frame = reshape(dec_u8, H, W, C);
recon_ok = isequal(dec_frame, orig_frame);

%% ===================== CHỈ SỐ ĐỊNH LƯỢNG (NHƯ BÀI BÁO) =====================
% Cắt cùng độ dài pixel gốc (bỏ pad Polar nếu có)
C1 = double(C1_u8(1:num_pixels));
C2 = double(C2_u8(1:num_pixels));
P  = double(plain_u8);

% 1) PSNR (càng thấp càng tốt với ciphertext vs plaintext)
MSE = mean((P - C1).^2);
if MSE == 0
    psnr_val = Inf;
else
    psnr_val = 10 * log10((255^2) / MSE);
end

% 2) Entropy (lý tưởng ~ 8.0)
ent_val = local_entropy(C1);

% 3) NSCR / UACI (lý tưởng ~ 99.6094% / 33.4635%)
nscr = 100 * sum(C1 ~= C2) / num_pixels;
uaci = 100 * sum(abs(C1 - C2)) / (num_pixels * 255);

% 4) Correlation pixel kề (bản mã ~ 0)
corr_orig = local_corr(P);
corr_enc  = local_corr(C1);

% 5) MSE giải mã (phải = 0 nếu đúng khóa)
mse_dec = mean((P - double(dec_u8)).^2);

fprintf('\n================ KẾT QUẢ ĐÁNH GIÁ VIDEO (STYLE BÀI BÁO) ================\n');
fprintf('Video file                 : %s\n', inputVideoFile);
fprintf('IV(P1) hex                 : %s\n', reshape(dec2hex(typecast(iv1,'uint8'))',1,[]));
fprintf('IV(P2) hex                 : %s\n', reshape(dec2hex(typecast(iv2,'uint8'))',1,[]));
fprintf('IV đổi khi flip 1 bit?     : %d\n', ~isequal(iv1, iv2));
fprintf('Khôi phục đúng frame?      : %d (MSE_dec = %.3e)\n', recon_ok, mse_dec);
fprintf('---------------------------------------------------------------------\n');
fprintf('1. PSNR (plain vs cipher)  : %8.4f dB   (càng thấp càng tốt)\n', psnr_val);
fprintf('2. Entropy (cipher)        : %8.4f bits (lý tưởng = 8.0)\n', ent_val);
fprintf('3. NSCR                    : %8.4f %%   (lý tưởng ≈ 99.6094)\n', nscr);
fprintf('4. UACI                    : %8.4f %%   (lý tưởng ≈ 33.4635)\n', uaci);
fprintf('5. Corr adjacent (plain)   : %8.4f\n', corr_orig);
fprintf('6. Corr adjacent (cipher)  : %8.4f      (lý tưởng ≈ 0)\n', corr_enc);
fprintf('=====================================================================\n');

fprintf('\n----- ĐỐI CHIẾU NGƯỠNG BÀI BÁO -----\n');
fprintf('Entropy > 7.9              : %s\n', tf(ent_val > 7.9));
fprintf('|NSCR - 99.6094| < 0.5     : %s\n', tf(abs(nscr - 99.6094) < 0.5));
fprintf('|UACI - 33.4635| < 1.0     : %s\n', tf(abs(uaci - 33.4635) < 1.0));
fprintf('|Corr_enc| < 0.05          : %s\n', tf(abs(corr_enc) < 0.05));
fprintf('PSNR < 15 dB               : %s\n', tf(psnr_val < 15));
fprintf('------------------------------------\n');

%% ===================== KPA / CPA ĐƠN GIẢN (NHƯ BÀI BÁO) =====================
fprintf('\n4. Kiểm tra KPA/CPA kiểu bài báo...\n');
% KPA: giả sử biết plaintext frame -> trích "keystream proxy" = XOR(plain, cipher)
% rồi dùng proxy đó để "giải" một frame khác / bản lật 1 bit -> BER ~ 50%
proxy = bitxor(uint8(P), uint8(C1));
fake_dec_from_C2 = bitxor(uint8(C2(1:num_pixels)), proxy);
ber_kpa = 100 * sum(fake_dec_from_C2(:) ~= plain2_u8(:)) / num_pixels;

% CPA: plaintext toàn 0
zero_plain = zeros(num_pixels, 1, 'uint8');
[C0_u8, iv0] = polar_aes_encrypt_bytes(zero_plain, N, K, Gn, Info_Indices, Frozen_Indices, KEY_FIXED);
proxy0 = bitxor(zero_plain, C0_u8(1:num_pixels));
fake_dec_cpa = bitxor(uint8(C1), proxy0);
ber_cpa = 100 * sum(fake_dec_cpa(:) ~= plain_u8(:)) / num_pixels;

fprintf('BER tái sử dụng keystream (KPA-style) : %6.2f %%  (lý tưởng ≈ 50)\n', ber_kpa);
fprintf('BER với plaintext toàn 0 (CPA-style)  : %6.2f %%  (lý tưởng ≈ 50)\n', ber_cpa);
fprintf('IV silence vs IV frame khác nhau?     : %d\n', ~isequal(iv0, iv1));

%% ===================== ĐỒ THỊ TRỰC QUAN =====================
% Fig 1: Frame gốc / mã / giải mã
figure('Name', 'Visual frames', 'Color', 'w', 'Position', [80 80 1200 380]);
subplot(1,3,1); imshow(orig_frame); title('Frame gốc');
subplot(1,3,2); imshow(enc_frame);  title('Frame mã hóa (nhiễu)');
subplot(1,3,3); imshow(dec_frame);  title(sprintf('Frame giải mã (OK=%d)', recon_ok));

% Fig 2: Histogram (thay cho histogram biên độ audio)
figure('Name', 'Histogram', 'Color', 'w', 'Position', [100 120 1000 420]);
subplot(1,2,1);
histogram(P, 0:256, 'FaceColor', [0.2 0.4 0.8], 'EdgeColor', 'none');
xlim([0 255]); grid on; title(sprintf('Histogram gốc'));
xlabel('Pixel value'); ylabel('Count');
subplot(1,2,2);
histogram(C1, 0:256, 'FaceColor', [0.85 0.25 0.2], 'EdgeColor', 'none');
xlim([0 255]); grid on; title(sprintf('Histogram mã hóa (H=%.4f)', ent_val));
xlabel('Pixel value'); ylabel('Count');

% Fig 3: Correlation scatter (thay scatter mẫu audio kề)
rng(0);
idx = randperm(num_pixels - 1, min(sampleScatter, num_pixels - 1));
figure('Name', 'Adjacent correlation', 'Color', 'w', 'Position', [120 140 1000 420]);
subplot(1,2,1);
scatter(P(idx), P(idx+1), 5, 'b', 'filled');
axis square; grid on; xlim([0 255]); ylim([0 255]);
xlabel('Pixel(i)'); ylabel('Pixel(i+1)');
title(sprintf('Tương quan gốc (R=%.4f)', corr_orig));
subplot(1,2,2);
scatter(C1(idx), C1(idx+1), 5, 'r', 'filled');
axis square; grid on; xlim([0 255]); ylim([0 255]);
xlabel('Pixel(i)'); ylabel('Pixel(i+1)');
title(sprintf('Tương quan mã hóa (R=%.4f)', corr_enc));

fprintf('\nHoàn tất. Xem Command Window + các figure.\n');

%% ===================== HÀM HỖ TRỢ =====================
function s = tf(cond)
if cond, s = 'TOT'; else, s = 'CHUA DAT'; end
end

function E = local_entropy(data)
p = histcounts(data, 0:256) / numel(data);
p = p(p > 0);
E = -sum(p .* log2(p));
end

function r = local_corr(vec)
a = vec(1:end-1);
b = vec(2:end);
R = corrcoef(a, b);
r = R(1,2);
end

function iv = generate_hash_iv(data_u8)
md = java.security.MessageDigest.getInstance('SHA-256');
h = typecast(md.digest(typecast(data_u8(:), 'int8')), 'int8');
iv = h(1:16);
end

function [cipher_u8, iv] = polar_aes_encrypt_bytes(plain_u8, N, K, Gn, Info_Indices, Frozen_Indices, key)
% Chia bitstream pixel thành khối K bit -> crypto-coding Polar + AES-CTR
plain_u8 = uint8(plain_u8(:));
bits = reshape(dec2bin(plain_u8, 8).' - '0', 1, []);
num_blocks = ceil(numel(bits) / K);
pad_len = num_blocks * K - numel(bits);
bits_pad = [bits, zeros(1, pad_len)];
u_matrix = reshape(bits_pad, K, []).';

iv = generate_hash_iv(plain_u8);
x_enc = run_cipher_ctr_dynamic_iv(u_matrix, num_blocks, N, K, Gn, Info_Indices, Frozen_Indices, key, iv);

x_stream = reshape(x_enc.', 1, []);
usable = floor(numel(x_stream)/8)*8;
cipher_u8 = uint8(bin2dec(reshape(char(x_stream(1:usable) + '0'), 8, []).'));
end

function plain_u8 = polar_aes_decrypt_bytes(cipher_u8, num_bytes, N, K, Gn, Info_Indices, key, iv)
% Giải mã khớp với encrypt: Polar "decode" (nhân Gn vì Gn*Gn=I trên GF(2) với bit-reversal setup này)
% Lưu ý: với SC decoder thật sẽ khác; ở đây dùng cấu trúc giống App/danhgia.m (mod(x*Gn,2)).
cipher_u8 = uint8(cipher_u8(:));
bits = reshape(dec2bin(cipher_u8, 8).' - '0', 1, []);
need_bits = ceil(num_bytes * 8 / K) * N; % mỗi block K bit plain -> N bit code
if numel(bits) < need_bits
    bits = [bits, zeros(1, need_bits - numel(bits))];
end
num_blocks = need_bits / N;
x_matrix = reshape(bits(1:need_bits), N, []).';

sKeySpec = javaObject('javax.crypto.spec.SecretKeySpec', key, 'AES');
aes_obj = javaMethod('getInstance', 'javax.crypto.Cipher', 'AES/CTR/NoPadding');
iv_spec = javaObject('javax.crypto.spec.IvParameterSpec', iv);
aes_obj.init(2, sKeySpec, iv_spec); % decrypt mode để lấy lại cùng keystream CTR

dec_u_bits = zeros(num_blocks, K);
for i = 1:num_blocks
    ks_bytes = aes_obj.update(zeros(1, ceil((N + 64)/8), 'int8'));
    bits_ks = reshape(dec2bin(typecast(ks_bytes, 'uint8'), 8).' - '0', 1, []);
    u_back = mod(x_matrix(i, :) * Gn, 2);
    dec_u_bits(i, :) = bitxor(u_back(Info_Indices), bits_ks(1:K));
end

dec_bits_all = reshape(dec_u_bits.', 1, []);
need = num_bytes * 8;
plain_u8 = uint8(bin2dec(reshape(char(dec_bits_all(1:need) + '0'), 8, []).'));
end

function x = run_cipher_ctr_dynamic_iv(u, blks, N, K, Gn, Inf, Frz, key, iv)
s = javaObject('javax.crypto.spec.SecretKeySpec', key, 'AES');
a = javaMethod('getInstance', 'javax.crypto.Cipher', 'AES/CTR/NoPadding');
a.init(1, s, javaObject('javax.crypto.spec.IvParameterSpec', iv));
x = zeros(blks, N);
for i = 1:blks
    ks = a.update(zeros(1, ceil((N + 64)/8), 'int8'));
    b = reshape(dec2bin(typecast(ks, 'uint8'), 8).' - '0', 1, []);
    u_f = zeros(1, N);
    u_f(Inf) = bitxor(u(i,:), b(1:K));
    u_f(Frz) = b(K+1:N);
    x(i,:) = mod(u_f * Gn, 2);
end
end
