close all; clear; clc;

%% 1. CONFIGURATION & DATA
N = 1024; R = 0.5; K = N * R;

% Import Java Crypto & Hashing
import javax.crypto.*; 
import javax.crypto.spec.*; 
import java.security.MessageDigest; 

audio_names = {'Animal', 'Drum', 'Piano', 'Car', 'Human'};
num_files = length(audio_names);

% Arrays to store metrics for final comparison
Store_PSNR = zeros(1, num_files);
Store_Entropy = zeros(1, num_files);
Store_Corr = zeros(1, num_files);
Store_NPCR = zeros(1, num_files);
Store_UACI = zeros(1, num_files);

% Polar Configuration
n_log = log2(N); Gn = 1; F = [1 0; 1 1];
for i = 1:n_log, Gn = kron(Gn, F); end
Reliability = bitrevorder(1:N); 
Info_Indices = Reliability(N-K+1:end);
Frozen_Indices = Reliability(1:N-K);

% GLOBAL KEY
KEY_FIXED = randi([-128 127], 1, 16, 'int8');
fprintf('>> GLOBAL KEY: %s\n', dec2hex(typecast(KEY_FIXED, 'uint8'))');

%% 2. PROCESSING LOOP
fprintf('\n==================================================================================\n');
fprintf('| %-8s | %-10s | %-10s | %-10s | %-10s | %-10s |\n', ...
    'Audio', 'PSNR(dB)', 'Entropy', 'Corr', 'NPCR(%)', 'UACI(%)');
fprintf('+----------+------------+------------+------------+------------+------------+\n');

for idx = 1:num_files
    % --- A. SIGNAL GENERATION ---
    name = audio_names{idx};
    Fs = 44100; t = linspace(0, 1, Fs)'; 
    
    switch lower(name)
        case 'animal', y = [sin(2*pi*500*t + 10*sin(2*pi*5*t)), sin(2*pi*510*t)];
        case 'drum',   y = [exp(-5*t).*sin(2*pi*50*t), exp(-5*t).*sin(2*pi*50*t)];
        otherwise,     y = [rand(Fs,1), rand(Fs,1)]; 
    end
    
    y_serial = y(:);
    y_uint8_orig = uint8((y_serial + 1) * 127.5);
    
    % Prepare P1 Data
    y_bits_raw = reshape(dec2bin(y_uint8_orig, 8).' - '0', 1, []);
    num_blocks = ceil(length(y_bits_raw) / K);
    pad_len = num_blocks * K - length(y_bits_raw);
    y_bits_padded = [y_bits_raw, zeros(1, pad_len)];
    u_matrix_1 = reshape(y_bits_padded, K, []).';
    
    % --- B. ENCRYPTION P1 ---
    P1_bytes = typecast(y_uint8_orig(:), 'int8');
    hash_iv_1 = generate_hash_iv(P1_bytes); 
    x_enc_1 = run_cipher_ctr_dynamic_iv(u_matrix_1, num_blocks, N, K, Gn, Info_Indices, Frozen_Indices, KEY_FIXED, hash_iv_1);
    
    % Convert to bytes
    x_stream_1 = reshape(x_enc_1.', 1, []);
    enc_bytes_1 = uint8(bin2dec(reshape(char(x_stream_1(1:floor(end/8)*8)+'0'), 8, []).'));
    
    % --- C. DIFFERENTIAL ATTACK (P2) ---
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
    
    % --- D. METRICS CALCULATION ---
    len_m = min(length(enc_bytes_1), length(enc_bytes_2));
    C1 = double(enc_bytes_1(1:len_m));
    C2 = double(enc_bytes_2(1:len_m));
    
    % NPCR & UACI
    D = (C1 ~= C2); 
    npcr = (sum(D) / len_m) * 100;
    uaci = (sum(abs(C1 - C2)) / (len_m * 255)) * 100;
    
    % PSNR
    y_enc_serial = (double(C1(:)) / 127.5) - 1; 
    len_p = min(length(y_serial), length(y_enc_serial));
    MSE = mean((y_serial(1:len_p) - y_enc_serial(1:len_p)).^2);
    psnr_val = 10 * log10(4 / MSE);
    
    % Entropy & Corr
    ent_val = entropy_calc(enc_bytes_1);
    R_mat = corrcoef(y_enc_serial(1:end-1), y_enc_serial(2:end));
    corr_val = R_mat(1,2);
    R_orig_mat = corrcoef(y_serial(1:end-1), y_serial(2:end));
    R_orig_val = R_orig_mat(1,2);

    % Store for Bar Charts
    Store_PSNR(idx) = psnr_val;
    Store_Entropy(idx) = ent_val;
    Store_Corr(idx) = corr_val;
    Store_NPCR(idx) = npcr;
    Store_UACI(idx) = uaci;
    
    fprintf('| %-8s | %10.4f | %10.4f | %10.5f | %10.2f | %10.2f |\n', ...
        name, psnr_val, ent_val, corr_val, npcr, uaci);
        
    % --- E. VISUALIZATION (SEPARATE PLOTS) ---
    
    % 1. SPECTROGRAM ANALYSIS
    figure('Name', [name ': Spectrogram Analysis'], 'Color', 'w');
    tiledlayout(1, 2, 'Padding', 'compact', 'TileSpacing', 'compact');
    
    nexttile; 
    spectrogram(y_serial(1:min(end, 20000)), 256, 128, 256, Fs, 'yaxis'); 
    title([name ' - Original Spectrogram'], 'FontSize', 22, 'FontWeight', 'bold', 'FontName', 'Times New Roman'); 
    set(gca, 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman'); colormap jet;
    
    nexttile; 
    spectrogram(y_enc_serial(1:min(end, 20000)), 256, 128, 256, Fs, 'yaxis');
    title([name ' - Encrypted Spectrogram'], 'FontSize', 22, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
    set(gca, 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman');
    
    % 2. HISTOGRAM ANALYSIS
    figure('Name', [name ': Histogram Analysis'], 'Color', 'w');
    tiledlayout(1, 2, 'Padding', 'compact', 'TileSpacing', 'compact');
    
    nexttile; 
    histogram(double(y_uint8_orig), 50, 'FaceColor', 'b', 'EdgeColor', 'none');
    title([name ' - Original Histogram'], 'FontSize', 22, 'FontWeight', 'bold', 'FontName', 'Times New Roman'); 
    xlim([0 255]); grid on; 
    set(gca, 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman');
    
    nexttile; 
    histogram(double(enc_bytes_1), 50, 'FaceColor', 'r', 'EdgeColor', 'none');
    title([name ' - Encrypted Histogram'], 'FontSize', 22, 'FontWeight', 'bold', 'FontName', 'Times New Roman'); 
    xlim([0 255]); grid on; 
    set(gca, 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman');
    
    % 3. CORRELATION ANALYSIS
    figure('Name', [name ': Correlation Analysis'], 'Color', 'w');
    tiledlayout(1, 2, 'Padding', 'compact', 'TileSpacing', 'compact');
    
    nexttile; 
    sample_len = min(length(y_serial), 5000);
    scatter(y_serial(1:sample_len-1), y_serial(2:sample_len), 15, 'b', 'filled');
    title({[name ' - Original Correlation']; ['R = ' num2str(R_orig_val, '%.4f')]}, 'FontSize', 22, 'FontWeight', 'bold', 'FontName', 'Times New Roman'); 
    xlabel('x(i)', 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman'); 
    ylabel('x(i+1)', 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman'); 
    axis square; grid on; 
    set(gca, 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman');
    
    nexttile; 
    sample_len_enc = min(length(y_enc_serial), 5000);
    scatter(y_enc_serial(1:sample_len_enc-1), y_enc_serial(2:sample_len_enc), 15, 'r', 'filled');
    title({[name ' - Encrypted Correlation']; ['R = ' num2str(corr_val, '%.4f')]}, 'FontSize', 22, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
    xlabel('y(i)', 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman'); 
    ylabel('y(i+1)', 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman'); 
    axis square; grid on; 
    set(gca, 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman');
    
    drawnow;
end
fprintf('+----------+------------+------------+------------+------------+------------+\n');

%% 3. COMPARISON CHARTS (METRICS)
% Convert names to categorical for X-axis
cats = categorical(audio_names);
cats = reordercats(cats, audio_names);

% -- Chart 1: PSNR --
figure('Name', 'Comparison: PSNR', 'Color', 'w');
bar(cats, Store_PSNR, 'FaceColor', [0.2 0.6 0.8]);
title('PSNR Comparison (dB)', 'FontSize', 22, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
ylabel('dB', 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman');
grid on; 
set(gca, 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman');

% -- Chart 2: Entropy --
figure('Name', 'Comparison: Entropy', 'Color', 'w');
bar(cats, Store_Entropy, 'FaceColor', [0.8 0.4 0.2]);
title('Entropy Comparison (Bits)', 'FontSize', 22, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
ylim([7.9 8.01]); % Zoom to ideal region
ylabel('Bits', 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman');
grid on; 
set(gca, 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman');

% -- Chart 3: Correlation --
figure('Name', 'Comparison: Correlation', 'Color', 'w');
bar(cats, Store_Corr, 'FaceColor', [0.4 0.8 0.4]);
title('Correlation Comparison (Encrypted)', 'FontSize', 22, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
ylabel('Coefficient R', 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman');
grid on; 
set(gca, 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman');

% -- Chart 4: NPCR --
figure('Name', 'Comparison: NPCR', 'Color', 'w');
bar(cats, Store_NPCR, 'FaceColor', [0.6 0.2 0.6]);
title('NPCR Comparison (%)', 'FontSize', 22, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
ylim([99 100]); % Zoom to 99-100%
ylabel('%', 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman');
grid on; 
set(gca, 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman');

% -- Chart 5: UACI --
figure('Name', 'Comparison: UACI', 'Color', 'w');
bar(cats, Store_UACI, 'FaceColor', [0.9 0.2 0.2]);
title('UACI Comparison (%)', 'FontSize', 22, 'FontWeight', 'bold', 'FontName', 'Times New Roman');
ylim([30 35]); % Zoom to ideal 33.4% region
ylabel('%', 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman');
grid on; 
set(gca, 'FontSize', 22, 'FontWeight', 'normal', 'FontName', 'Times New Roman');

%% --- HELPER FUNCTIONS ---
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