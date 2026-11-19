close all; clear; clc;

%% 1. CONFIGURATION & DATA
% Bản video của MaHoa.m: giữ nguyên thuật toán Polar + AES-CTR (bài báo),
% đổi đối tượng từ mẫu âm thanh sang khung hình video.
N = 1024; R = 0.5; K = N * R;

import javax.crypto.*; %#ok<JAPIMAIN>
import javax.crypto.spec.*; %#ok<JAPIMAIN>
import java.security.MessageDigest; %#ok<JAPIMAIN>

inputVideoFile = 'Dog.mp4';
maxSide = 160;   % thu nhỏ frame khi demo (đặt [] = giữ nguyên kích thước)

% Các mốc frame dùng như "samples" (tương tự Animal/Drum/Piano...)
frame_names = {'Frame1', 'FrameMid', 'FrameLast'};
frame_pos   = [0.00, 0.50, 0.99];   % tỉ lệ thời gian trong video
num_files = length(frame_names);

Store_PSNR = zeros(1, num_files);
Store_Entropy = zeros(1, num_files);
Store_Corr = zeros(1, num_files);
Store_NPCR = zeros(1, num_files);
Store_UACI = zeros(1, num_files);

% Polar Configuration (giống MaHoa.m)
n_log = log2(N); Gn = 1; F = [1 0; 1 1];
for i = 1:n_log, Gn = kron(Gn, F); end
Reliability = bitrevorder(1:N);
Info_Indices = Reliability(N-K+1:end);
Frozen_Indices = Reliability(1:N-K);

% GLOBAL KEY (cố định để tái lập; muốn random thì dùng randi như MaHoa.m)
KEY_FIXED = int8([10, -20, 30, -40, 50, -60, 70, -80, 90, -100, 110, -120, 15, -25, 35, -45]);
fprintf('>> GLOBAL KEY: %s\n', reshape(dec2hex(typecast(KEY_FIXED, 'uint8'))', 1, []));

if ~isfile(inputVideoFile)
    error('Không tìm thấy "%s". Đặt video cùng thư mục script.', inputVideoFile);
end

vinfo = VideoReader(inputVideoFile);
fprintf('>> Video: %s | %.2fs | %.2f fps\n', inputVideoFile, vinfo.Duration, vinfo.FrameRate);

%% 2. PROCESSING LOOP
fprintf('\n==================================================================================\n');
fprintf('| %-10s | %-10s | %-10s | %-10s | %-10s | %-10s |\n', ...
    'Frame', 'PSNR(dB)', 'Entropy', 'Corr', 'NPCR(%)', 'UACI(%)');
fprintf('+------------+------------+------------+------------+------------+------------+\n');

for idx = 1:num_files
    name = frame_names{idx};

    % --- A. ĐỌC KHUNG HÌNH (thay cho sinh tín hiệu audio) ---
    t_sec = min(max(frame_pos(idx) * vinfo.Duration, 0), max(vinfo.Duration - 1/vinfo.FrameRate, 0));
    vinfo.CurrentTime = t_sec;
    if hasFrame(vinfo)
        frame = readFrame(vinfo);
    else
        error('Không đọc được frame "%s" tại t=%.3fs', name, t_sec);
    end

    if ~isempty(maxSide)
        [H0, W0, ~] = size(frame);
        sc = maxSide / max(H0, W0);
        if sc < 1
            frame = imresize(frame, sc);
        end
    end

    [H, W, Ch] = size(frame);
    y_uint8_orig = frame(:);                 % dữ liệu frame (uint8), column-major
    num_bytes = numel(y_uint8_orig);

    % Prepare P1 Data (y hệt MaHoa.m)
    y_bits_raw = reshape(dec2bin(y_uint8_orig, 8).' - '0', 1, []);
    num_blocks = ceil(length(y_bits_raw) / K);
    pad_len = num_blocks * K - length(y_bits_raw);
    y_bits_padded = [y_bits_raw, zeros(1, pad_len)];
    u_matrix_1 = reshape(y_bits_padded, K, []).';

    % --- B. ENCRYPTION P1 (thuật toán bài báo / MaHoa.m) ---
    P1_bytes = typecast(y_uint8_orig(:), 'int8');
    hash_iv_1 = generate_hash_iv(P1_bytes);
    x_enc_1 = run_cipher_ctr_dynamic_iv(u_matrix_1, num_blocks, N, K, Gn, Info_Indices, Frozen_Indices, KEY_FIXED, hash_iv_1);

    x_stream_1 = reshape(x_enc_1.', 1, []);
    enc_bytes_1 = uint8(bin2dec(reshape(char(x_stream_1(1:floor(end/8)*8)+'0'), 8, []).'));

    % Ghép lại thành frame mã hóa để quan sát (cắt đúng số byte frame)
    enc_frame = reshape(enc_bytes_1(1:num_bytes), H, W, Ch);

    % --- C. DIFFERENTIAL ATTACK (P2): lật 1 bit byte đầu ---
    y_uint8_mod = y_uint8_orig;
    y_uint8_mod(1) = bitxor(y_uint8_mod(1), 1);

    y_bits_mod = reshape(dec2bin(y_uint8_mod, 8).' - '0', 1, []);
    y_bits_padded_2 = [y_bits_mod, zeros(1, pad_len)];
    u_matrix_2 = reshape(y_bits_padded_2, K, []).';

    P2_bytes = typecast(y_uint8_mod(:), 'int8');
    hash_iv_2 = generate_hash_iv(P2_bytes);
    x_enc_2 = run_cipher_ctr_dynamic_iv(u_matrix_2, num_blocks, N, K, Gn, Info_Indices, Frozen_Indices, KEY_FIXED, hash_iv_2);

    x_stream_2 = reshape(x_enc_2.', 1, []);
    enc_bytes_2 = uint8(bin2dec(reshape(char(x_stream_2(1:floor(end/8)*8)+'0'), 8, []).'));

    % --- D. METRICS (cùng bộ chỉ số MaHoa.m / bài báo) ---
    len_m = min([length(enc_bytes_1), length(enc_bytes_2), num_bytes]);
    C1 = double(enc_bytes_1(1:len_m));
    C2 = double(enc_bytes_2(1:len_m));
    P  = double(y_uint8_orig(1:len_m));

    % NPCR & UACI
    D = (C1 ~= C2);
    npcr = (sum(D) / len_m) * 100;
    uaci = (sum(abs(C1 - C2)) / (len_m * 255)) * 100;

    % PSNR trên miền 8-bit ảnh (thay vì [-1,1] của audio)
    MSE = mean((P - C1).^2);
    psnr_val = 10 * log10((255^2) / MSE);

    % Entropy & Corr
    ent_val = entropy_calc(enc_bytes_1(1:len_m));
    R_mat = corrcoef(C1(1:end-1), C1(2:end));
    corr_val = R_mat(1,2);
    R_orig_mat = corrcoef(P(1:end-1), P(2:end));
    R_orig_val = R_orig_mat(1,2);

    Store_PSNR(idx) = psnr_val;
    Store_Entropy(idx) = ent_val;
    Store_Corr(idx) = corr_val;
    Store_NPCR(idx) = npcr;
    Store_UACI(idx) = uaci;

    fprintf('| %-10s | %10.4f | %10.4f | %10.5f | %10.2f | %10.2f |\n', ...
        name, psnr_val, ent_val, corr_val, npcr, uaci);

    % --- E. VISUALIZATION ---
    % 1. FRAME VIEW (thay Spectrogram của audio)
    figure('Name', [name ': Frame Analysis'], 'Color', 'w');
    tiledlayout(1, 2, 'Padding', 'compact', 'TileSpacing', 'compact');
    nexttile; imshow(frame); title([name ' - Original Frame'], ...
        'FontSize', 18, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
    nexttile; imshow(enc_frame); title([name ' - Encrypted Frame'], ...
        'FontSize', 18, 'FontWeight', 'bold', 'FontName', 'Times New Roman');

    % 2. HISTOGRAM
    figure('Name', [name ': Histogram Analysis'], 'Color', 'w');
    tiledlayout(1, 2, 'Padding', 'compact', 'TileSpacing', 'compact');
    nexttile;
    histogram(P, 50, 'FaceColor', 'b', 'EdgeColor', 'none');
    title([name ' - Original Histogram'], 'FontSize', 18, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
    xlim([0 255]); grid on;
    set(gca, 'FontSize', 16, 'FontName', 'Times New Roman');
    nexttile;
    histogram(C1, 50, 'FaceColor', 'r', 'EdgeColor', 'none');
    title([name ' - Encrypted Histogram'], 'FontSize', 18, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
    xlim([0 255]); grid on;
    set(gca, 'FontSize', 16, 'FontName', 'Times New Roman');

    % 3. CORRELATION
    figure('Name', [name ': Correlation Analysis'], 'Color', 'w');
    tiledlayout(1, 2, 'Padding', 'compact', 'TileSpacing', 'compact');
    sample_len = min(len_m, 5000);
    nexttile;
    scatter(P(1:sample_len-1), P(2:sample_len), 15, 'b', 'filled');
    title({[name ' - Original Correlation']; ['R = ' num2str(R_orig_val, '%.4f')]}, ...
        'FontSize', 18, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
    xlabel('x(i)'); ylabel('x(i+1)'); axis square; grid on; xlim([0 255]); ylim([0 255]);
    set(gca, 'FontSize', 16, 'FontName', 'Times New Roman');
    nexttile;
    scatter(C1(1:sample_len-1), C1(2:sample_len), 15, 'r', 'filled');
    title({[name ' - Encrypted Correlation']; ['R = ' num2str(corr_val, '%.4f')]}, ...
        'FontSize', 18, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
    xlabel('y(i)'); ylabel('y(i+1)'); axis square; grid on; xlim([0 255]); ylim([0 255]);
    set(gca, 'FontSize', 16, 'FontName', 'Times New Roman');

    drawnow;
end
fprintf('+------------+------------+------------+------------+------------+------------+\n');

%% 3. COMPARISON CHARTS (giống MaHoa.m)
cats = categorical(frame_names);
cats = reordercats(cats, frame_names);

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

fprintf('\nXong. Chạy trên MATLAB: mở MaHoaVideo.m rồi Run.\n');
fprintf('Gợi ý: maxSide=[] nếu muốn đánh giá full resolution (chậm hơn).\n');

%% --- HELPER FUNCTIONS (copy từ MaHoa.m) ---
function iv_bytes = generate_hash_iv(data_bytes)
    md = java.security.MessageDigest.getInstance('SHA-256');
    hash = typecast(md.digest(data_bytes), 'int8');
    iv_bytes = hash(1:16);
end

function x_encoded = run_cipher_ctr_dynamic_iv(u_mat, n_blks, N, K, Gn, Info, Frozen, key_bytes, iv_base)
    sKeySpec = javaObject('javax.crypto.spec.SecretKeySpec', key_bytes, 'AES');
    aes_obj = javaMethod('getInstance', 'javax.crypto.Cipher', 'AES/CTR/NoPadding');

    x_encoded = zeros(n_blks, N);

    iv_spec = javaObject('javax.crypto.spec.IvParameterSpec', iv_base);
    aes_obj.init(1, sKeySpec, iv_spec);

    for i = 1:n_blks
        req_bytes = ceil((N + 64)/8);
        zeros_in = zeros(1, req_bytes, 'int8');
        keystream_bytes = aes_obj.update(zeros_in);

        bits_out = reshape(dec2bin(typecast(keystream_bytes, 'uint8'), 8).' - '0', 1, []);
        Mask = bits_out(1:K);
        Froz = bits_out(K+1:N);

        u_full = zeros(1, N);
        u_full(Info) = bitxor(u_mat(i, :), Mask);
        u_full(Frozen) = Froz;
        x_encoded(i, :) = mod(u_full * Gn, 2);
    end
end

function E = entropy_calc(data)
    p = histcounts(data, 0:256) / length(data); p = p(p > 0);
    E = -sum(p .* log2(p));
end
