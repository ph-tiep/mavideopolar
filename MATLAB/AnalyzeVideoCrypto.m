close all; clear; clc;

% ================= AnalyzeVideoCrypto.m =================
% Đánh giá JCM trên khung hình Dog.mp4.
% Muc tieu chi so nhu Table III–IV: NPCR ≈ 99.61%, UACI ≈ 33.46%,
% Entropy ≈ 7.999, Corr ≈ 0. IV = SHA-256(frame) de avalanche nhu thi nghiem bao.

inputVideoFile = 'Dog.mp4';
maxSide = 320;   % thu nhỏ để tính nhanh; [] = full frame

N = 1024; R = 0.5; K = N * R;
KEY_GLOBAL = int8([10, -20, 30, -40, 50, -60, 70, -80, 90, -100, 110, -120, 15, -25, 35, -45]);

if ~isfile(inputVideoFile)
    error('Không tìm thấy %s', inputVideoFile);
end

[Info_Indices, Frozen_Indices] = polar_indices(N, K);
polar_selftest(KEY_GLOBAL, N, K, Info_Indices, Frozen_Indices);

frame_names = {'Frame1', 'FrameMid', 'FrameLast'};
frame_pos   = [0.00, 0.50, 0.99];
num_files = numel(frame_names);

Store_PSNR = zeros(1, num_files);
Store_Entropy = zeros(1, num_files);
Store_Corr = zeros(1, num_files);
Store_NPCR = zeros(1, num_files);
Store_UACI = zeros(1, num_files);
Store_CorrOrig = zeros(1, num_files);
Store_DecFrame = cell(num_files, 1);

Save_plain = cell(num_files, 1);
Save_cipher = cell(num_files, 1);
Save_frame = cell(num_files, 1);
Save_encframe = cell(num_files, 1);
Save_HWC = zeros(num_files, 3);

vinfo = VideoReader(inputVideoFile);
fprintf('>> Video: %s | %.2fs | %.2f fps\n', inputVideoFile, vinfo.Duration, vinfo.FrameRate);

fprintf('\n==================================================================================\n');
fprintf('| %-10s | %-10s | %-10s | %-10s | %-10s | %-10s | %-10s |\n', ...
    'Frame', 'PSNR(dB)', 'Entropy', 'Corr(O)', 'Corr(E)', 'NPCR(%)', 'UACI(%)');
fprintf('+------------+------------+------------+------------+------------+------------+------------+\n');

for idx = 1:num_files
    name = frame_names{idx};
    t_sec = min(max(frame_pos(idx) * vinfo.Duration, 0), max(vinfo.Duration - 1/vinfo.FrameRate, 0));
    vinfo.CurrentTime = t_sec;
    if ~hasFrame(vinfo)
        error('Không đọc được %s tại t=%.3fs', name, t_sec);
    end
    frame = readFrame(vinfo);

    if ~isempty(maxSide)
        [H0, W0, ~] = size(frame);
        sc = maxSide / max(H0, W0);
        if sc < 1
            frame = imresize(frame, sc);
        end
    end

    [H, W, Ch] = size(frame);
    y_uint8_orig = frame(:);
    num_bytes = numel(y_uint8_orig);

    [enc_bytes_1, iv1] = encrypt_polar_aes(y_uint8_orig, KEY_GLOBAL, N, K, Info_Indices, Frozen_Indices);
    enc_frame = reshape(enc_bytes_1(1:num_bytes), H, W, Ch);

    % P2: lật 1 bit => SHA-256 đổi IV => keystream mới (avalanche Table III JCM)
    y_uint8_mod = y_uint8_orig;
    y_uint8_mod(1) = bitxor(y_uint8_mod(1), 1);
    [enc_bytes_2, iv2] = encrypt_polar_aes(y_uint8_mod, KEY_GLOBAL, N, K, Info_Indices, Frozen_Indices);

    rec = decrypt_polar_aes(enc_bytes_1, num_bytes, KEY_GLOBAL, iv1, N, K, Info_Indices);
    recon_ok = isequal(rec(:), y_uint8_orig(:));

    len_m = min(numel(enc_bytes_1), numel(enc_bytes_2));
    C1 = double(enc_bytes_1(1:len_m));
    C2 = double(enc_bytes_2(1:len_m));
    P  = double(y_uint8_orig);

    npcr = 100 * sum(C1 ~= C2) / len_m;
    uaci = 100 * sum(abs(C1 - C2)) / (len_m * 255);

    % PSNR trên ảnh 8-bit (khác audio: audio MaHoa.m dùng 4/MSE vì biên độ [-1,1])
    Pvis = P;
    Cvis = double(enc_bytes_1(1:num_bytes));
    MSE = mean((Pvis - Cvis).^2);
    psnr_val = 10 * log10((255^2) / MSE);

    ent_val = entropy_calc(enc_bytes_1);
    R_mat = corrcoef(Cvis(1:end-1), Cvis(2:end));
    corr_val = R_mat(1, 2);
    R_orig = corrcoef(P(1:end-1), P(2:end));
    R_orig_val = R_orig(1, 2);

    Store_PSNR(idx) = psnr_val;
    Store_Entropy(idx) = ent_val;
    Store_Corr(idx) = corr_val;
    Store_CorrOrig(idx) = R_orig_val;
    Store_NPCR(idx) = npcr;
    Store_UACI(idx) = uaci;

    Save_plain{idx} = y_uint8_orig;
    Save_cipher{idx} = enc_bytes_1;
    Save_frame{idx} = frame;
    Save_encframe{idx} = enc_frame;
    Save_HWC(idx, :) = [H, W, Ch];
    Store_DecFrame{idx} = reshape(rec, H, W, Ch);

    fprintf('| %-10s | %10.4f | %10.4f | %10.5f | %10.5f | %10.2f | %10.2f |\n', ...
        name, psnr_val, ent_val, R_orig_val, corr_val, npcr, uaci);
    fprintf('  khôi phục đúng=%d | IV đổi khi flip 1 bit=%d\n', recon_ok, ~isequal(iv1, iv2));

    % --- Hình: frame (thay spectrogram) ---
    figure('Name', [name ': Frame Analysis'], 'Color', 'w');
    tiledlayout(1, 3, 'Padding', 'compact', 'TileSpacing', 'compact');
    nexttile; imshow(frame); title([name ' - Original'], ...
        'FontSize', 16, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
    nexttile; imshow(enc_frame); title([name ' - Encrypted'], ...
        'FontSize', 16, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
    nexttile; imshow(Store_DecFrame{idx}); title([name ' - Decrypted'], ...
        'FontSize', 16, 'FontWeight', 'bold', 'FontName', 'Times New Roman');

    % --- Histogram ---
    figure('Name', [name ': Histogram Analysis'], 'Color', 'w');
    tiledlayout(1, 2, 'Padding', 'compact', 'TileSpacing', 'compact');
    nexttile;
    histogram(P, 50, 'FaceColor', 'b', 'EdgeColor', 'none');
    title([name ' - Original Histogram'], 'FontSize', 18, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
    xlim([0 255]); grid on; set(gca, 'FontSize', 16, 'FontName', 'Times New Roman');
    nexttile;
    histogram(C1, 50, 'FaceColor', 'r', 'EdgeColor', 'none');
    title([name ' - Encrypted Histogram'], 'FontSize', 18, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
    xlim([0 255]); grid on; set(gca, 'FontSize', 16, 'FontName', 'Times New Roman');

    % --- Correlation ---
    figure('Name', [name ': Correlation Analysis'], 'Color', 'w');
    tiledlayout(1, 2, 'Padding', 'compact', 'TileSpacing', 'compact');
    % Rải mẫu trên cả khung. 5000 byte đầu của FrameLast chỉ là mép đen,
    % mọi điểm chồng tại (0,0) dù R tính trên cả ảnh.
    step = max(1, floor((num_bytes - 1) / 5000));
    idx = 1:step:(num_bytes - 1);
    nexttile;
    scatter(P(idx), P(idx + 1), 15, 'b', 'filled');
    title({[name ' - Original Correlation']; ['R = ' num2str(R_orig_val, '%.4f')]}, ...
        'FontSize', 18, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
    xlabel('x(i)'); ylabel('x(i+1)'); axis square; grid on; xlim([0 255]); ylim([0 255]);
    set(gca, 'FontSize', 16, 'FontName', 'Times New Roman');
    nexttile;
    scatter(Cvis(idx), Cvis(idx + 1), 15, 'r', 'filled');
    title({[name ' - Encrypted Correlation']; ['R = ' num2str(corr_val, '%.4f')]}, ...
        'FontSize', 18, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
    xlabel('y(i)'); ylabel('y(i+1)'); axis square; grid on; xlim([0 255]); ylim([0 255]);
    set(gca, 'FontSize', 16, 'FontName', 'Times New Roman');

    % --- Pho tan so 2D (thay Spectrogram cua audio) ---
    figure('Name', [name ': Frequency Spectrum'], 'Color', 'w');
    tiledlayout(1, 2, 'Padding', 'compact', 'TileSpacing', 'compact');
    spec_orig = log(1 + abs(fftshift(fft2(rgb2gray_local(frame)))));
    spec_enc  = log(1 + abs(fftshift(fft2(rgb2gray_local(enc_frame)))));
    nexttile; imagesc(spec_orig); axis image off; colormap(gca, jet);
    title([name ' - Original Spectrum'], 'FontSize', 16, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
    nexttile; imagesc(spec_enc); axis image off; colormap(gca, jet);
    title([name ' - Encrypted Spectrum'], 'FontSize', 16, 'FontWeight', 'bold', 'FontName', 'Times New Roman');

    drawnow;
end
fprintf('+------------+------------+------------+------------+------------+------------+------------+\n');

fprintf('\n========== BANG KET QUA (kieu JCM, khong so sanh bai khac) ==========\n');
fprintf('Table I  - Correlation\n');
fprintf('| %-10s | %-12s | %-12s |\n', 'Sample', 'Original R', 'Encrypted R');
for i = 1:num_files
    fprintf('| %-10s | %12.5f | %12.5f |\n', frame_names{i}, Store_CorrOrig(i), Store_Corr(i));
end
fprintf('Table II - Entropy (ly thuyet = 8.0)\n');
for i = 1:num_files
    fprintf('| %-10s | %10.4f |\n', frame_names{i}, Store_Entropy(i));
end
fprintf('Table III - NPCR %% (ly thuyet ≈ 99.61)\n');
for i = 1:num_files
    fprintf('| %-10s | %10.2f |\n', frame_names{i}, Store_NPCR(i));
end
fprintf('Table IV - UACI %% (ly thuyet ≈ 33.46)\n');
for i = 1:num_files
    fprintf('| %-10s | %10.2f |\n', frame_names{i}, Store_UACI(i));
end
fprintf('Table V - PSNR dB (cang thap cang tot)\n');
for i = 1:num_files
    fprintf('| %-10s | %10.4f |\n', frame_names{i}, Store_PSNR(i));
end
fprintf('===================================================================\n');

%% KPA / CPA (Section C bai JCM, Fig. 9-10)
fprintf('\n----- KPA / CPA (JCM: BER ly tuong ~ 50%%) -----\n');
% KPA: biet Frame1 (Animal), trich proxy = XOR(plain, cipher), dung de "giai" FrameMid (Drum)
P_A = Save_plain{1};  C_A = Save_cipher{1}(1:numel(P_A));
P_B = Save_plain{2};  C_B = Save_cipher{2}(1:numel(P_B));
nAB = min(numel(P_A), numel(P_B));
proxy_kpa = bitxor(P_A(1:nAB), C_A(1:nAB));
fake_kpa  = bitxor(C_B(1:nAB), proxy_kpa);
ber_kpa = 100 * bit_ber(fake_kpa, P_B(1:nAB));
fprintf('KPA  (Frame1 -> FrameMid) : BER = %6.2f %%  (JCM Animal->Drum ~ 49.56%%)\n', ber_kpa);

% CPA: plaintext toan 0 ("Silence"), trich keystream, dung len FrameMid
P0 = zeros(numel(P_A), 1, 'uint8');
[C0, ~] = encrypt_polar_aes(P0, KEY_GLOBAL, N, K, Info_Indices, Frozen_Indices);
C0 = C0(1:numel(P_A));
n0 = min(numel(C0), numel(P_B));
proxy_cpa = bitxor(P0(1:n0), C0(1:n0));
fake_cpa  = bitxor(C_B(1:n0), proxy_cpa);
ber_cpa = 100 * bit_ber(fake_cpa, P_B(1:n0));
fprintf('CPA  (all-zero -> FrameMid): BER = %6.2f %%  (JCM Silence->Drum ~ 50.08%%)\n', ber_cpa);

H2 = Save_HWC(2,1); W2 = Save_HWC(2,2); C2c = Save_HWC(2,3);
err_kpa = reshape(abs(double(fake_kpa(1:H2*W2*C2c)) - double(P_B(1:H2*W2*C2c))), H2, W2, C2c);
err_cpa = reshape(abs(double(fake_cpa(1:H2*W2*C2c)) - double(P_B(1:H2*W2*C2c))), H2, W2, C2c);

figure('Name', 'KPA / CPA error map (JCM Fig.9-10)', 'Color', 'w');
tiledlayout(1, 2, 'Padding', 'compact', 'TileSpacing', 'compact');
nexttile; imshow(uint8(err_kpa));
title(sprintf('KPA error map (BER = %.2f%%)', ber_kpa), 'FontSize', 16, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
nexttile; imshow(uint8(err_cpa));
title(sprintf('CPA error map (BER = %.2f%%)', ber_cpa), 'FontSize', 16, 'FontWeight', 'bold', 'FontName', 'Times New Roman');

fprintf('\n----- DOI CHIEU TABLE JCM (NPCR≈99.61, UACI≈33.46, H≈7.999, BER≈50) -----\n');
fprintf('Entropy > 7.9          : '); disp_ok(all(Store_Entropy > 7.9));
fprintf('|NPCR - 99.6094| < 0.5 : '); disp_ok(all(abs(Store_NPCR - 99.6094) < 0.5));
fprintf('|UACI - 33.4635| < 1.0 : '); disp_ok(all(abs(Store_UACI - 33.4635) < 1.0));
fprintf('|Corr_enc| < 0.05      : '); disp_ok(all(abs(Store_Corr) < 0.05));
fprintf('PSNR < 15 dB           : '); disp_ok(all(Store_PSNR < 15));
fprintf('|BER_KPA - 50| < 5     : '); disp_ok(abs(ber_kpa - 50) < 5);
fprintf('|BER_CPA - 50| < 5     : '); disp_ok(abs(ber_cpa - 50) < 5);

%% Bar charts so sánh (như MaHoa.m)
cats = reordercats(categorical(frame_names), frame_names);

figure('Name', 'Comparison: PSNR', 'Color', 'w');
bar(cats, Store_PSNR, 'FaceColor', [0.2 0.6 0.8]);
title('PSNR Comparison (dB)', 'FontSize', 22, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
ylabel('dB'); grid on; set(gca, 'FontSize', 18, 'FontName', 'Times New Roman');

figure('Name', 'Comparison: Entropy', 'Color', 'w');
bar(cats, Store_Entropy, 'FaceColor', [0.8 0.4 0.2]);
title('Entropy Comparison (Bits)', 'FontSize', 22, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
ylim([7.9 8.01]); ylabel('Bits'); grid on; set(gca, 'FontSize', 18, 'FontName', 'Times New Roman');

figure('Name', 'Comparison: Correlation', 'Color', 'w');
bar(cats, Store_Corr, 'FaceColor', [0.4 0.8 0.4]);
title('Correlation Comparison (Encrypted)', 'FontSize', 22, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
ylabel('Coefficient R'); grid on; set(gca, 'FontSize', 18, 'FontName', 'Times New Roman');

figure('Name', 'Comparison: NPCR', 'Color', 'w');
bar(cats, Store_NPCR, 'FaceColor', [0.6 0.2 0.6]);
title('NPCR Comparison (%)', 'FontSize', 22, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
ylim([99 100]); ylabel('%'); grid on; set(gca, 'FontSize', 18, 'FontName', 'Times New Roman');

figure('Name', 'Comparison: UACI', 'Color', 'w');
bar(cats, Store_UACI, 'FaceColor', [0.9 0.2 0.2]);
title('UACI Comparison (%)', 'FontSize', 22, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
ylim([30 35]); ylabel('%'); grid on; set(gca, 'FontSize', 18, 'FontName', 'Times New Roman');

fprintf('\nXong phân tích. Chạy AnalyzeVideoCrypto.m độc lập (không cần Encrypt trước).\n');

function disp_ok(cond)
if cond
    fprintf('TOT\n');
else
    fprintf('CHUA DAT\n');
end
end

function g = rgb2gray_local(img)
if size(img, 3) == 3
    g = double(img(:,:,1)) * 0.299 + double(img(:,:,2)) * 0.587 + double(img(:,:,3)) * 0.114;
else
    g = double(img);
end
end

function r = bit_ber(a, b)
ba = bytes_to_bits(a);
bb = bytes_to_bits(b);
n = min(numel(ba), numel(bb));
r = sum(ba(1:n) ~= bb(1:n)) / n;
end
%% ================= CÁC HÀM HỖ TRỢ (DÁN Ở CUỐI FILE) =================

function [cipher_u8, iv_bytes] = encrypt_polar_aes(plain_u8, key_bytes, N, K, Info_Indices, Frozen_Indices)
    import javax.crypto.*;
    import javax.crypto.spec.*;
    import java.security.MessageDigest;

    md = MessageDigest.getInstance('SHA-256');
    plain_int8 = typecast(plain_u8(:), 'int8');
    hash_bytes = md.digest(plain_int8);
    iv_bytes = typecast(hash_bytes(1:16), 'int8');

    bits_raw = reshape(dec2bin(plain_u8, 8).' - '0', 1, []);
    num_blocks = ceil(length(bits_raw) / K);
    pad_len = num_blocks * K - length(bits_raw);
    bits_padded = [bits_raw, zeros(1, pad_len)];
    u_mat = reshape(bits_padded, K, []).';

    n_log = log2(N); Gn = 1; F = [1 0; 1 1];
    for i = 1:n_log, Gn = kron(Gn, F); end

    sKeySpec = javaObject('javax.crypto.spec.SecretKeySpec', key_bytes, 'AES');
    ivSpec = javaObject('javax.crypto.spec.IvParameterSpec', iv_bytes);
    aes_obj = javaMethod('getInstance', 'javax.crypto.Cipher', 'AES/CTR/NoPadding');
    aes_obj.init(1, sKeySpec, ivSpec); 

    x_encoded = zeros(num_blocks, N);
    for i = 1:num_blocks
        req_bytes = ceil((N + 64)/8);
        zeros_in = zeros(1, req_bytes, 'int8');
        keystream_bytes = aes_obj.update(zeros_in); 
        
        bits_out = reshape(dec2bin(typecast(keystream_bytes, 'uint8'), 8).' - '0', 1, []);
        Mask = bits_out(1:K);       
        Froz = bits_out(K+1:N);     
        
        u_full = zeros(1, N);
        u_full(Info_Indices) = bitxor(u_mat(i, :), Mask); 
        u_full(Frozen_Indices) = Froz;
        
        x_encoded(i, :) = mod(u_full * Gn, 2); 
    end

    x_stream = reshape(x_encoded.', 1, []);
    cipher_u8 = uint8(bin2dec(reshape(char(x_stream(1:floor(end/8)*8)+'0'), 8, []).'));
end

function dec_u8 = decrypt_polar_aes(cipher_u8, num_target_bytes, key_bytes, iv_bytes, N, K, Info_Indices)
    import javax.crypto.*;
    import javax.crypto.spec.*;
    
    n_log = log2(N); Gn = 1; F = [1 0; 1 1];
    for i = 1:n_log, Gn = kron(Gn, F); end
    
    bits_raw = reshape(dec2bin(cipher_u8, 8).' - '0', 1, []);
    num_blocks = floor(length(bits_raw) / N);
    x_mat = reshape(bits_raw(1:num_blocks*N), N, []).';
    
    sKeySpec = javaObject('javax.crypto.spec.SecretKeySpec', key_bytes, 'AES');
    ivSpec = javaObject('javax.crypto.spec.IvParameterSpec', iv_bytes);
    aes_obj = javaMethod('getInstance', 'javax.crypto.Cipher', 'AES/CTR/NoPadding');
    aes_obj.init(2, sKeySpec, ivSpec); 
    
    plain_bits = zeros(1, num_blocks * K);
    for i = 1:num_blocks
        u_full = mod(x_mat(i, :) * Gn, 2);
        u_info = u_full(Info_Indices); 
        
        req_bytes = ceil((N + 64)/8);
        zeros_in = zeros(1, req_bytes, 'int8');
        keystream_bytes = aes_obj.update(zeros_in); 
        bits_out = reshape(dec2bin(typecast(keystream_bytes, 'uint8'), 8).' - '0', 1, []);
        Mask = bits_out(1:K); 
        
        plain_bits((i-1)*K + 1 : i*K) = bitxor(u_info, Mask);
    end
    
    num_target_bits = num_target_bytes * 8;
    plain_bits = plain_bits(1:num_target_bits);
    dec_u8 = uint8(bin2dec(reshape(char(plain_bits + '0'), 8, []).'));
end

function E = entropy_calc(data)
    p = histcounts(data, 0:256) / length(data); p = p(p > 0);
    E = -sum(p .* log2(p));
end

function b = bytes_to_bits(bytes)
    b = reshape(dec2bin(bytes, 8).' - '0', 1, []);
end